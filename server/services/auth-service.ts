import * as argon2 from "argon2";
import * as jwt from "jsonwebtoken";
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
  login(email: string, password: string): any;
  generateToken(userId: string, isInternal: boolean): any;
  isInternalUser(token: string): any;
}

@Service("AuthService")
class AuthService implements AuthServiceI {
  #JWTSignature: string;

  constructor(
    @Inject("JWT_PRIVATE_KEY") JWT_PRIVATE_KEY: string,
    @Inject("Logger") private logger,
    @Inject("UserService") private UserService,
  ) {
    this.logger = logger;
    this.UserService = UserService;
    this.#JWTSignature = JWT_PRIVATE_KEY;
  }

  private async _sanitizeData(data) {
    if (data.password) {
      delete data.password;
    }
    return data;
  }

  public generateToken(userId: string, isInternal = false) {
    //TODO: implement anon data; Should we decrease the session expiration?
    return jwt.sign({ id: userId, isAnon: false, isInternal }, this.#JWTSignature, {
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

  public async register(email: string, password: string, firstName: string): Promise<any> {
    this.logger.info("AuthService::register:: checking if user exists...");
    const queryResult = await this.UserService.getByEmail(email);

    //TODO: Check for existing session too..send 409

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

  public async login(email: string, password: string): Promise<any> {
    try {
      this.logger.info("AuthService:login:: checking if user exists...");

      const userRecord = await this.UserService.getByEmail(email);

      if (!userRecord) {
        const error = "User does not exist!";
        this.logger.info(`AuthService:register::failed::${error}`);
        //TODO: Set error code
        throw new Error(error);
      } else {
        const passwordVerified = await argon2.verify(userRecord.password, password);
        if (!passwordVerified) {
          this.logger.info("AuthService:register::failed:: Incorrect password");
          //TODO: Set different error code
          throw new Error("Incorrect password");
        }
      }

      this.logger.info("AuthService:login::success:: User verified");
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
