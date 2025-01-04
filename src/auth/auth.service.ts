import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';

import { Model } from 'mongoose';
import * as bcryptjs from 'bcryptjs';

import { User } from './entities/user.entity';
import { SignInResponse } from './interfaces/sign-in.interface';
import { SignUpResponse } from './interfaces/sign-up.interface';

import {
  CreateUserDto,
  SignInUserDto,
  SignUpUserDto
} from './dto/create-user.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';

@Injectable()
export class AuthService {

  constructor(
    @InjectModel(User.name) private userModel: Model<User>,
    private jwtService: JwtService,
  ) { }

  async signIn(signInUser: SignInUserDto): Promise<SignInResponse> {
    const user = await this.userModel.findOne({ email: signInUser.email });

    if (!user) {
      throw new UnauthorizedException('User does not exists');
    }
    if (!user.isActive) {
      throw new UnauthorizedException('User is not active');
    }
    if (!bcryptjs.compareSync(signInUser.password, user.password)) {
      throw new UnauthorizedException('Invalid password');
    }

    const userReturn = user.toJSON();
    delete userReturn.password;

    return {
      ...userReturn,
      token: await this.jwtService.signAsync({ id: user.id }),
    };
  }

  async signUp(signUpUser: SignUpUserDto): Promise<SignUpResponse> {
    const user = await this.create(signUpUser);

    return {
      ...user,
      token: await this.jwtService.signAsync({ id: user._id }),
    };
  }

  async create(CreateUserDto: CreateUserDto): Promise<User> {
    try {
      const existingUser = await this.userModel.findOne({
        email: CreateUserDto.email
      });
      if (existingUser) {
        throw new UnauthorizedException('User already exists');
      }

      const user = new this.userModel({
        email: CreateUserDto.email,
        name: CreateUserDto.name,
        password: this.encriptPassword(CreateUserDto.password),
      });

      await user.save();

      const userReturn = user.toJSON();
      delete userReturn.password;

      return userReturn;

    } catch (error) {
      throw new UnauthorizedException(`Error creating user: ${error.message}`);
    }
  }

  private encriptPassword(password: string): string {
    return bcryptjs.hashSync(password, 10);
  }

  async refreshToken(request: Request): Promise<SignInResponse> {
    const user = await this.userModel.findById(request['user'].id);

    if (!user) {
      throw new UnauthorizedException('User does not exists');
    }
    if (!user.isActive) {
      throw new UnauthorizedException('User is not active');
    }
    
    return {
      ...user.toJSON(),
      token: await this.jwtService.signAsync({ id: user._id }),
    };
  }

  extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers.authorization?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}
