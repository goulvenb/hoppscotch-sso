import { Strategy, Profile } from '@node-saml/passport-saml';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthService } from '../auth.service';
import { UserService } from 'src/user/user.service';
import * as O from 'fp-ts/Option';
import * as E from 'fp-ts/Either';
import { ConfigService } from '@nestjs/config';
import { validateEmail } from 'src/utils';
import { AUTH_EMAIL_NOT_PROVIDED_BY_OAUTH } from 'src/errors';
import { Profile as PassportProfile } from 'passport';

@Injectable()
export class SamlStrategy extends PassportStrategy(Strategy) {
  samlFields = {
    email: undefined,
    firstName: undefined,
    lastName: undefined,
    username: undefined,
  };

  constructor(
    private authService: AuthService,
    private usersService: UserService,
    private configService: ConfigService,
  ) {
    super({
      callbackUrl: configService.get<string>('INFRA.SAML_CALLBACK_URL'),
      entryPoint: configService.get<string>('INFRA.SAML_ENTRYPOINT'),
      issuer: configService.get<string>('INFRA.SAML_ISSUER'),
      idpCert: configService.get<string>('INFRA.SAML_IDP_CERT'),
    });

    this.samlFields = {
      email: configService.get<string>('INFRA.SAML_FIELD_NAME_EMAIL'),
      firstName: configService.get<string>('INFRA.SAML_FIELD_NAME_FIRSTNAME'),
      lastName: configService.get<string>('INFRA.SAML_FIELD_NAME_LASTNAME'),
      username: configService.get<string>('INFRA.SAML_FIELD_NAME_USERNAME'),
    };
  }

  async validate(profile: Profile, done) {
    // prettier-ignore
    // To ignore warnings on ternary operators
    const samlProfile = {
      provider: 'saml',
      id: profile['nameID'],
      displayName: (
        profile[this.samlFields['firstName']] && profile[this.samlFields['lastName']]
          ? `${profile[this.samlFields['firstName']]} ${profile[this.samlFields['lastName']]}`
          : (
            profile[this.samlFields['username']]
              ? profile[this.samlFields['username']]
              : (
                profile[this.samlFields['email']]
                  ? profile[this.samlFields['email']]
                  : profile['nameID']
              )
          )
      ),
      username: profile[this.samlFields['username']],
      name: {
        familyName: profile[this.samlFields['lastName']],
        givenName: profile[this.samlFields['firstName']],
      },
      emails: [{ value: profile[this.samlFields['email']] }],
    } as PassportProfile;

    const email = samlProfile['emails'][0]['value'];

    if (!validateEmail(email))
      throw new UnauthorizedException(AUTH_EMAIL_NOT_PROVIDED_BY_OAUTH);

    const user = await this.usersService.findUserByEmail(email);

    if (O.isNone(user)) {
      const createdUser = await this.usersService.createUserViaMagicLink(email);
      return createdUser;
    }

    /**
     * * displayName and photoURL maybe null if user logged-in via magic-link before SSO
     */
    if (!user.value.displayName || !user.value.photoURL) {
      const updatedUser = await this.usersService.updateUserDetails(
        user.value,
        samlProfile,
      );
      if (E.isLeft(updatedUser)) {
        throw new UnauthorizedException(updatedUser.left);
      }
    }

    /**
     * * Check to see if entry for Google is present in the Account table for user
     * * If user was created with another provider findUserByEmail may return true
     */
    const providerAccountExists =
      await this.authService.checkIfProviderAccountExists(
        user.value,
        samlProfile,
      );

    if (O.isNone(providerAccountExists))
      await this.usersService.createProviderAccount(
        user.value,
        profile['sessionIndex'],
        undefined,
        samlProfile,
      );

    return user.value;
  }
}
