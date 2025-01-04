import { IsEmail, IsString, MinLength } from "class-validator";

export class CreateUserDto { 
  @IsEmail()
  email: string;

  @IsString()
  name: string;

  @MinLength(6)
  password: string;
}

export class SignInUserDto {
  @IsEmail()
  email: string;

  @IsString()
  password: string;
}

export class SignUpUserDto {
  @IsEmail()
  email: string;

  @IsString()
  password: string;

  @IsString()
  name: string;
}