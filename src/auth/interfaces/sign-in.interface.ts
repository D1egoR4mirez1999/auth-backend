import { User } from "../entities/user.entity";

export interface SignInResponse extends User {
  token: string;
}