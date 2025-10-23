import {
  IsNotEmpty,
  IsString,
  MinLength,
  IsOptional,
  IsEmail,
} from 'class-validator';

export class RegisterDto {
  @IsEmail()
  email: string;

  @IsString()
  @IsNotEmpty()
  @MinLength(8, { message: 'Password must be at least 8 characters long' })
  password: string;

  @IsString()
  @IsOptional()
  name?: string;
}
