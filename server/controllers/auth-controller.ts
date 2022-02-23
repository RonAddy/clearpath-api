import { Container } from "typedi";

import { Request, Response } from "express";

import { APIResponse } from "../utils/types";
import { AuthServiceI } from "../services/auth-service";
import { Logger } from "winston";

function AuthController() {
  const AuthService: AuthServiceI = Container.get("AuthService");
  const logger: Logger = Container.get("Logger");

  return {
    async register(req: Request, res: Response) {
      try {
        logger.info("AuthController::register:: Starting response cycle");

        if (AuthService.isAuthenticated(req)) {
          logger.error("AuthController::register:: error CONFLICT");
          return res.status(409).json({ error: `REGISTER::Session is already attached to request!!` });
        }

        const { email, password, firstName } = req.body;
        const { user, token } = await AuthService.register(email, password, firstName);

        let _ = AuthService.attachSignedCookie(res, token);

        logger.info("AuthController::register::success");
        return res.status(200).json({ message: "success", user, token });
      } catch (e) {
        logger.info(`AuthController::register:: ${e}`);
        await req.session.destroy;
        return res.status(401).json({ error: `${e}` });
      }
    },

    async login(req: Request, res: Response, next) {
      try {
        logger.info("AuthController:login:: Starting response cycle");

        if (AuthService.isAuthenticated(req)) {
          logger.error("AuthController::login:: error CONFLICT");
          return res.status(409).json({ error: `LOGIN::Session is already attached to request!!` });
        }

        const { email, password } = req.body;
        const { user, token } = await AuthService.createSession(email, password);

        let _ = AuthService.attachSignedCookie(res, token);

        logger.info("AuthController:login:: Success");
        return res.status(200).json({ message: "success", user, token });
      } catch (e) {
        logger.info(`AuthController:login:: ${e}`);
        await req.session.destroy;
        return res.status(401).json({ error: `${e}` });
      }
    },

    async logout(req: Request, res: Response) {
      try {
        logger.info("AuthController:logout:: Starting response cycle");

        if (req.session) {
          await req.session.destroy((err) => {
            if (err) {
              throw new Error("AuthController:logout:: Unable to log out");
            } else {
              res.clearCookie("clrpth:ath:tkn");
              res.clearCookie("__session");
              logger.info("AuthController:logout:: Cookies cleared and session destroyed!!");
              return res.status(200).json({ message: "Logout successful" });
            }
          });
        } else {
          return res.end();
        }
      } catch (e) {
        logger.info(`AuthController:logout::error:: ${e}`);
        return res.status(400).json({ error: `${e}` });
      }
    },

    async refresh(req: Request, res: Response, next) {
      try {
        logger.info("AuthController:refresh:: Starting response cycle");
        const { user, token } = await AuthService.refreshFromSession(req);

        logger.info("AuthController::refresh::success");
        return res.status(200).json({ message: "success", user, token });
      } catch (e) {
        logger.info(`AuthController:refresh::error:: ${e}`);
        return res.status(400).json({ error: `${e}` });
      }
    },
  };
}

const _AuthControllerIns = AuthController();

export default _AuthControllerIns;
