import { User } from "../entities/user.entity";

export interface SignUpResponse extends User {
  token: string;
}