import { IsEmail, IsOptional, IsString } from 'class-validator';

export class CreateUserDto {
  @IsEmail()
  email: string;

  @IsString()
  name: string;

  @IsOptional()
  phone: string;
}

export class CreateManyUsersDto {
  @IsEmail()
  email: string;

  @IsString()
  name: string;

  @IsOptional()
  phone: string;
}
