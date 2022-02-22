import {
  IsEmail,
  IsString,
  IsNotEmpty,
  MinLength,
  IsOptional,
} from 'class-validator';

export class LoginDto {
  @IsString()
  @IsEmail()
  @IsOptional()
  email: string;

  @IsString()
  @IsOptional()
  username: string;

  @IsString()
  @IsNotEmpty()
  @MinLength(8)
  password: string;
}
