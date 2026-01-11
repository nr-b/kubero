import { PassportStrategy } from '@nestjs/passport';
import { Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import * as client from 'openid-client';
import {
  Strategy,
  type VerifyFunction,
  type StrategyOptions,
  type AuthenticateOptions,
} from 'openid-client/passport';
import * as dotenv from 'dotenv';
dotenv.config();

@Injectable()
export class OidcStrategy extends PassportStrategy(Strategy) {
  public static isConfigPresent() {
    const required_fields = [
      'OIDC_ISSUER',
      'OIDC_CLIENT_ID',
      'OIDC_CLIENT_SECRET',
      'OIDC_CLIENT_CALLBACKURL',
      'OIDC_USER_ID_FIELD',
      'OIDC_USER_USERNAME_FIELD',
      'OIDC_USER_EMAIL_FIELD',
    ];

    for (const f of required_fields) {
      if (!(f in process.env)) {
        console.log(`${f} missing`);
        return false;
      }
    }

    return true;
  }

  public static async make() {
    if (!OidcStrategy.isConfigPresent()) {
      throw new Error('OIDC config not present');
    }

    let openIdConfig = await client.discovery(
      new URL(process.env.OIDC_ISSUER || ''),
      process.env.OIDC_CLIENT_ID || '',
      process.env.OIDC_CLIENT_SECRET || '',
    );

    return new OidcStrategy(openIdConfig);
  }

  constructor(openIdConfig: client.Configuration) {
    const logger = new Logger(OidcStrategy.name);

    if (!OidcStrategy.isConfigPresent()) {
      throw new Error('OIDC config not present');
    }

    super({
      name: 'openidconnect',
      config: openIdConfig,
      scope: process.env.OIDC_CLIENT_SCOPE,
      callbackURL: process.env.OIDC_CLIENT_CALLBACKURL,
    } as StrategyOptions);
  }

  async validate(profile: any, _refreshToken: string) {
    const claims = profile.claims() || {};
    const id = claims[process.env.OIDC_USER_ID_FIELD || ''];
    const username = claims[process.env.OIDC_USER_USERNAME_FIELD || ''];
    const email = claims[process.env.OIDC_USER_EMAIL_FIELD || ''];
    if (!claims || !id || !username || !email) {
      throw new UnauthorizedException();
    }

    let role = '';
    if (process.env.OIDC_USER_ROLE_FIELD) {
      role = claims[process.env.OIDC_USER_ROLE_FIELD];
    }

    return {
      id,
      username,
      email,
      role,
    };
  }
}
