import { IsEmail, IsString, IsNotEmpty, MinLength } from 'class-validator';

export class RegisterDto {
  @IsEmail()
  @IsNotEmpty()
  @IsString()
  email: string;

  @IsString()
  @MinLength(4)
  @IsNotEmpty()
  username: string;

  @IsString()
  @IsNotEmpty()
  phone_number: string;

  @IsString()
  @IsNotEmpty()
  @MinLength(8)
  password: string;
}
