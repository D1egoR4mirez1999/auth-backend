import {
  Controller,
  Post,
  Body,
  Get,
  Req,
  UseGuards,
} from '@nestjs/common';
import { Request } from 'express';

import { AuthService } from './auth.service';
import { AuthGuard } from './guards/auth.guard';

import {
  CreateUserDto,
  SignInUserDto,
  SignUpUserDto
} from './dto/create-user.dto';

import { SignInResponse } from './interfaces/sign-in.interface';


@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) { }

  @Post()
  create(@Body() CreateUserDto: CreateUserDto) {
    return this.authService.create(CreateUserDto);
  }

  @Post('/signin')
  signIn(@Body() signInUser: SignInUserDto) {
    return this.authService.signIn(signInUser);
  }

  @Post('/signup')
  signUp(@Body() signUpUser: SignUpUserDto) {
    return this.authService.signUp(signUpUser);
  }

  @UseGuards(AuthGuard)
  @Get('/refresh-token')
  refreshToken(@Req() request: Request): Promise<SignInResponse> {
    return this.authService.refreshToken(request);
  }
}
