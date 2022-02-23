import * as argon2 from "argon2";
import { Request, Response } from "express";
import jwt, { Jwt } from "jsonwebtoken";
import { Service, Inject } from "typedi";
import { SESSION_MAX_AGE } from "../config";

export interface AuthServiceI {
  /** TODO:
   *
   * 1) findSession()
   * 2) Create cron job to clean out old sessions
   *    - Maybe create task once we create a session, give it expiry as when to complete it
   * 3) anonLogin()
   * fix types below!
   */
  register(email: string, password: string, firstName: string): any;
  createSession(email: string, password: string): any;
  generateToken(userId: string, isInternal: boolean): any;
  isInternalUser(token: string): any;
  isAuthenticated(req: Request, isFromLogin?: boolean): boolean;
  attachSignedCookie(res: Response, token: string): void;
  isTokenExpired(jwt: Jwt): boolean;
  refreshFromSession(req: Request);
}

@Service("AuthService")
class AuthService implements AuthServiceI {
  #JWTSignature: string;
  #tokenIdentifier: string;

  constructor(
    @Inject("JWT_PRIVATE_KEY") JWT_PRIVATE_KEY: string,
    @Inject("Logger") private logger,
    @Inject("UserService") private UserService,
  ) {
    this.logger = logger;
    this.UserService = UserService;
    this.#JWTSignature = JWT_PRIVATE_KEY;
    this.#tokenIdentifier = "clrpth:ath:tkn";
  }

  private _sanitizeData(data) {
    if (data.password) {
      delete data.password;
    }
    return data;
  }

  public isTokenExpired = (jwt: Jwt) => {
    /* Check that session has not expired */
    const expiry = jwt.payload.exp;
    const todaysDate = new Date().getTime();
    const expired = expiry < todaysDate;

    if (expired) {
      this.logger.error(`AuthService:: Token has expired!: \n
      Expiry: ${new Date(expiry).toLocaleString().split(",")[0]}`);
      return true;
    }
    return false;
  };

  public isAuthenticated(req: Request) {
    const signedCookieJWT = req.signedCookies[this.#tokenIdentifier];
    const bearerToken = req.headers.authorization;
    const isMobileClient = req.useragent.isMobile;

    const tokensMatch = signedCookieJWT === bearerToken;
    const missingToken = !signedCookieJWT || !bearerToken;

    if (!tokensMatch || missingToken) {
      if (isMobileClient && bearerToken) {
        //Hack to get mobile working. Mobile clients do not have signedCookies
        return true;
      }
      return false;
    }
    const tokens = [signedCookieJWT, bearerToken];
    let passChecks = true;

    for (let i: number = 0; i < tokens.length; i++) {
      //@ts-ignore
      const verifiedToken: Jwt = jwt.verify(tokens[i], this.#JWTSignature, { complete: true });
      const isExpired = this.isTokenExpired(verifiedToken);
      if (isExpired) {
        passChecks = false;
        this.logger.info(`AuthService::isAuthenticated:: Token is expired---`);
      }
      break;
    }

    return passChecks;
  }

  public generateToken(userId: string, isInternal = false) {
    //TODO: implement anon data; Should we decrease the session expiration?
    /* User info is used by passport strategy */
    /* Add session iD */
    return jwt.sign({ user: { id: userId, isAnon: false, isInternal } }, this.#JWTSignature, {
      expiresIn: SESSION_MAX_AGE,
    });
  }

  public isInternalUser(token: string) {
    const data = jwt.verify(token, this.#JWTSignature);
    const descriptor = Object.getOwnPropertyDescriptor(data, "isInternal");

    if (descriptor) {
      return !!descriptor.value;
    } else {
      return false;
    }
  }

  public attachSignedCookie(res: Response, token: string) {
    //move to config
    res.cookie(this.#tokenIdentifier, token, {
      httpOnly: true,
      sameSite: "none",
      signed: true,
      secure: true,
    });
  }

  public async refreshFromSession(req: Request) {
    try {
      const isMobileClient = req.useragent.isMobile;
      const requestToken = isMobileClient ? req.headers.authorization : req.signedCookies[this.#tokenIdentifier];

      //@ts-ignore
      const verifiedToken: Jwt = jwt.verify(requestToken, this.#JWTSignature, { complete: true });
      const userId = verifiedToken.payload.user.id;
      const userDetails = await this.UserService.getById(userId);

      return { user: this._sanitizeData(userDetails), token: requestToken };
    } catch (e) {
      this.logger.error(`AuthService::refreshFromSession::failed -- ${e}`);
      throw new Error(`AuthService::refreshFromSession:: Could not to refresh session!`);
    }
  }

  public async register(email: string, password: string, firstName: string): Promise<any> {
    this.logger.info("AuthService::register:: checking if user exists...");
    const queryResult = await this.UserService.getByEmail(email);

    //TODO: Check for existing session too..send 409 (should that be here or controller?)

    if (queryResult) {
      this.logger.info("AuthService::register::failed:: User exists");
      throw new Error("A user with this email already exists");
    }

    const hashedPassword = await argon2.hash(password);
    const userRecord = await this.UserService.createWithEmailAndPassword(email, hashedPassword, firstName);

    this.logger.info("AuthService:register::success:: User created!");
    return {
      user: userRecord,
      token: this.generateToken(userRecord.id),
    };
  }

  public async createSession(email: string, password: string): Promise<any> {
    try {
      this.logger.info("AuthService:createSession:: checking if user exists...");

      const userRecord = await this.UserService.getByEmail(email);

      if (!userRecord) {
        const error = "User does not exist!";
        this.logger.info(`AuthService:createSession::failed::${error}`);
        //TODO: Set error code
        throw new Error(error);
      } else {
        const passwordVerified = await argon2.verify(userRecord.password, password);
        if (!passwordVerified) {
          this.logger.info("AuthService:createSession::failed:: Incorrect password");
          //TODO: Set different error code
          throw new Error("Incorrect password");
        }
      }

      this.logger.info("AuthService:createSession::success:: User verified", userRecord);
      return {
        user: this._sanitizeData(userRecord),
        token: this.generateToken(userRecord.id, userRecord.internal_user),
      };
    } catch (e) {
      throw new Error(`AuthServiceError::${e}`);
    }
  }
}

export default AuthService;
