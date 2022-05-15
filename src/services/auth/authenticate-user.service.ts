const bcrypt = require('bcrypt')
import { sign } from 'jsonwebtoken'
import { PrismaShowUserModel } from '@models/user/show-user.model'

interface ShowUserRequest {
  email: string
  password: string
}

export class AuthenticateUserService {
  constructor(private prismaShowUserModel: PrismaShowUserModel) {}

  async execute(request: ShowUserRequest) {
    const { email: emailRequest, password } = request

    const user = await this.prismaShowUserModel.findByEmail(emailRequest)

    if (!user) {
      throw new Error('User or password invalid')
    }

    const isPasswordValid = await bcrypt.compare(password, user.password)

    if (!isPasswordValid) {
      throw new Error('User or password invalid')
    }

    const token = sign({}, process.env.JWT_SECRET_KEY as string, {
      subject: user.id,
      expiresIn: '20s',
    })

    return {
      token,
    }
  }
}
