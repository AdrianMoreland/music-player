import { decode } from 'next-auth/jwt';
import { dbUserCheck } from '../common/dbFunctions';

async function authjwtMiddleware(req, res, next) {
  const sessionCookie = req.headers.cookie
      ?.split(';')
      .find(c => c.trim().startsWith('next-auth.session-token=') || c.trim().startsWith('__Secure-next-auth.session-token='));

  if (!sessionCookie) {
    console.log("No session cookie found");
    return res.status(401).json({ message: 'Unauthorized' });
  }

  const token = sessionCookie.split('=')[1];

  try {
    const decoded = await decode({
      token: token,
      secret: process.env.NEXTAUTH_SECRET,
    });

    if (!decoded) {
      console.log("Failed to decode token");
      return res.status(401).json({ message: 'Unauthorized' });
    }

    req.auth = { userId: decoded.sub };

    const dbUser = await dbUserCheck(decoded);

    if (dbUser.status === -1) {
      return res.status(401).json({ status: -1, message: 'Your sign up has not been approved. Please wait for the approval email 🙏' });
    }

    req.auth.dbUser = dbUser;
    next();
  } catch (error) {
    console.log("Error decoding token:", error);
    res.status(401).json({ message: 'Unauthorized' });
  }
}

export default authjwtMiddleware;