import { type User } from '@prisma/client';
import prisma from '@/lib/prisma';
import LogMessage from '@/decorators/log-message.decorator';

export default class UserService {
  @LogMessage<[User]>({ message: 'test-decorator' })
  public async createUser(data: User) {
    const user = await prisma.user.create({ data });
    return user;
  }

  public async createManyUsers(users: User[], verify: boolean) {
    if (verify) {
      // Verify users
      users = users.map((user) => ({ ...user, verified: true }));
    }
    const createdUsers = await prisma.user.createMany({
      data: users,
      skipDuplicates: true,
    });
    return createdUsers;
  }
}
