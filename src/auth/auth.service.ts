import { ConflictException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import { RegisterInputTypes } from './types/register.types';

@Injectable()
export class AuthService {
  constructor(private readonly prisma: PrismaService) {}

  async register(registerInput: RegisterInputTypes) {
    const { email, password, name } = registerInput;

    // check if user already exists
    const existingUser = await this.prisma.user.findUnique({
      where: {
        email,
      },
    });

    if (existingUser) {
      // ConflictException is a 409 status code -> Resource already exists
      throw new ConflictException('User with this email already exists');
    }

    // Hash password using bcrypt -> 10 is the number of salt rounds
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create User
    const newUser = await this.prisma.user.create({
      data: {
        email,
        password: hashedPassword,
        name,
      },
    });

    console.log(newUser);
    return {
      message: 'User created successfully',
      user: newUser,
    };
  }
}
