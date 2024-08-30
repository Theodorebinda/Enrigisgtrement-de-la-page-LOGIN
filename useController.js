const bcrypt = require('bcrypt');
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

const saltRounds = 10;

async function createUser(email, password, name) {
  try {
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    
    const newUser = await prisma.user.create({
      data: {
        email,
        password: hashedPassword,
        name,
      },
    });

    return newUser;
  } catch (error) {
    console.error('Error creating user:', error);
    throw error;
  }
}

async function authenticateUser(email, password) {
  try {
    const user = await prisma.user.findUnique({
      where: { email },
    });

    if (!user) {
      throw new Error('User not found');
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      throw new Error('Invalid password');
    }

    return user;
  } catch (error) {
    console.error('Error authenticating user:', error);
    throw error;
  }
}

module.exports = { createUser, authenticateUser };
