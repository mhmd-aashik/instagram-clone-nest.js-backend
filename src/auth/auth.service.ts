import {
  ConflictException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import {
  LoginInputTypes,
  RegisterInputTypes,
  ResetPasswordInputTypes,
} from './types';
import { v4 as uuidv4 } from 'uuid';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

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
      select: {
        id: true,
        email: true,
        name: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    // Generate JWT tokens
    const tokens = await this.generateTokens(newUser.id);

    return {
      message: 'Registration successful! Welcome to our platform.',
      user: {
        id: newUser.id,
        email: newUser.email,
        name: newUser.name,
      },
      ...tokens,
    };
  }

  async login(loginInput: LoginInputTypes) {
    const { email, password } = loginInput;

    // Find user
    const user = await this.prisma.user.findUnique({
      where: { email },
    });

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Generate tokens
    const tokens = await this.generateTokens(user.id);

    return {
      message: 'Login successful!',
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
      },
      ...tokens,
    };
  }

  async logout(refreshToken: string) {
    // Find and revoke the refresh token
    await this.prisma.refreshToken.updateMany({
      where: {
        jti: refreshToken,
        isRevoked: false,
      },
      data: {
        isRevoked: true,
      },
    });

    return {
      message: 'Logout successful! You have been signed out.',
    };
  }

  async requestPasswordReset(email: string) {
    // Find user
    const user = await this.prisma.user.findUnique({
      where: { email },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Generate reset token
    const resetToken = uuidv4();
    const hashedToken = await bcrypt.hash(resetToken, 10);

    // Store reset token in database
    const expiresAt = new Date();
    expiresAt.setMinutes(expiresAt.getMinutes() + 15); // 15 minutes expiry

    await this.prisma.passwordResetToken.create({
      data: {
        userId: user.id,
        hashedToken,
        expiresAt,
      },
    });

    return {
      message: 'Password reset email sent successfully',
      token: resetToken,
      expiresAt: expiresAt.toISOString(),
    };
  }

  async resendPasswordReset(email: string) {
    // Find user
    const user = await this.prisma.user.findUnique({
      where: { email },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Invalidate all existing reset tokens for this user
    await this.prisma.passwordResetToken.updateMany({
      where: {
        userId: user.id,
        isUsed: false,
      },
      data: {
        isUsed: true,
      },
    });

    // Generate new reset token
    const resetToken = uuidv4();
    const hashedToken = await bcrypt.hash(resetToken, 10);

    // Store new reset token in database
    const expiresAt = new Date();
    expiresAt.setMinutes(expiresAt.getMinutes() + 15); // 15 minutes expiry

    await this.prisma.passwordResetToken.create({
      data: {
        userId: user.id,
        hashedToken,
        expiresAt,
      },
    });

    return {
      message: 'New password reset email sent successfully',
      token: resetToken,
      expiresAt: expiresAt.toISOString(),
    };
  }

  async resetPassword(resetPasswordInput: ResetPasswordInputTypes) {
    const { token, newPassword } = resetPasswordInput;

    // find all non-expired,non-used reset password tokens
    const resetTokens = await this.prisma.passwordResetToken.findMany({
      where: {
        isUsed: false,
        expiresAt: {
          gt: new Date(),
        },
      },
      include: {
        user: true,
      },
    });

    // Find the matching token by comparing hashed tokens
    let matchedToken: (typeof resetTokens)[0] | null = null;
    for (const storedToken of resetTokens) {
      const isMatch = await bcrypt.compare(token, storedToken.hashedToken);

      if (isMatch) {
        matchedToken = storedToken;
        break;
      }
    }

    if (!matchedToken) {
      throw new UnauthorizedException(
        'Invalid or expired reset password token',
      );
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // update user password
    await this.prisma.user.update({
      where: {
        id: matchedToken.user.id,
      },
      data: {
        password: hashedPassword,
      },
    });

    return {
      message: 'Password reset successful',
    };
  }

  async refreshToken(refreshToken: string) {
    try {
      // verify refresh token
      const payload = this.jwtService.verify(refreshToken, {
        secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
      }) as unknown as { sub: string; jti: string };

      // Check if refresh token exists in database and is not revoked
      const storeToken = await this.prisma.refreshToken.findUnique({
        where: {
          jti: payload.jti,
        },
      });

      if (!storeToken) {
        throw new UnauthorizedException('Invalid refresh token');
      }

      if (storeToken.isRevoked) {
        throw new UnauthorizedException('Refresh token has been revoked');
      }

      if (storeToken.expiresAt < new Date()) {
        throw new UnauthorizedException('Refresh token has expired');
      }

      await this.prisma.refreshToken.update({
        where: {
          id: storeToken.id,
        },
        data: {
          isRevoked: true,
        },
      });

      // generate new tokens
      const newAccessToken = await this.generateTokens(payload.sub);

      return {
        message: 'Token refreshed successfully',
        ...newAccessToken,
      };
    } catch (error) {
      console.error(error);
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  private async generateTokens(userId: string) {
    const jti = uuidv4();

    // create access token using configured JWT module
    // sub is the subject of the token, which is the user id
    const accessToken = this.jwtService.sign({
      sub: userId,
    });

    // Create refresh token with jti
    const refreshToken = this.jwtService.sign({
      sub: userId,
      jti,
    });

    // set refresh token expires at to 30 days
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 30);

    // create refresh token in database
    await this.prisma.refreshToken.create({
      data: {
        jti,
        userId,
        expiresAt,
      },
    });

    return {
      accessToken,
      refreshToken,
    };
  }

  async getAllUsers() {
    const users = await this.prisma.user.findMany({
      select: {
        id: true,
        email: true,
        name: true,
        createdAt: true,
        updatedAt: true,
      },
    });
    return {
      message: 'Users retrieved successfully',
      users,
    };
  }

  async getMyId(id: string) {
    const user = await this.prisma.user.findUnique({
      omit: {
        password: true,
      },
      where: {
        id,
      },
    });
    return {
      message: 'User information retrieved successfully',
      user,
    };
  }
}
