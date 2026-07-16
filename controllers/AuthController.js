const sha1 = require('sha1');
const { v4: uuid4 } = require('uuid');
const redisClient = require('../utils/redis');
const dbClient = require('../utils/db');

class AuthController {
  static async getConnect(req, res) {
    try {
      const authHeader = req.headers.authorization;

      // Check if authorization header exists
      if (!authHeader) {
        return res.status(401).json({ error: 'Unauthorized' });
      }

      // Check if it's a Basic auth header
      const parts = authHeader.split(' ');
      if (parts.length !== 2 || parts[0] !== 'Basic') {
        return res.status(401).json({ error: 'Unauthorized' });
      }

      let credentials;
      try {
        // Decode Base64 - this will throw if invalid
        credentials = Buffer.from(parts[1], 'base64').toString('utf-8');
      } catch (err) {
        return res.status(401).json({ error: 'Unauthorized' });
      }

      // Check if credentials contain a colon
      const colonIndex = credentials.indexOf(':');
      if (colonIndex === -1) {
        return res.status(401).json({ error: 'Unauthorized' });
      }

      const email = credentials.substring(0, colonIndex);
      const password = credentials.substring(colonIndex + 1);

      if (!email || !password) {
        return res.status(401).json({ error: 'Unauthorized' });
      }

      const query = { email, password: sha1(password) };
      const user = await dbClient.db.collection('users').findOne(query);

      if (!user) {
        return res.status(401).json({ error: 'Unauthorized' });
      }

      const token = uuid4();
      await redisClient.set(`auth_${token}`, user._id.toString(), 86400);

      return res.status(200).json({ token });
    } catch (error) {
      console.error('Error in getConnect:', error);
      return res.status(500).json({ error: 'Internal Server Error' });
    }
  }

  static async getDisconnect(req, res) {
    try {
      const token = req.header('X-Token');
      if (!token) {
        return res.status(401).json({ error: 'Unauthorized' });
      }

      const userId = await redisClient.get(`auth_${token}`);
      if (!userId) {
        return res.status(401).json({ error: 'Unauthorized' });
      }

      await redisClient.del(`auth_${token}`);
      return res.status(204).send();
    } catch (error) {
      console.error('Error in getDisconnect:', error);
      return res.status(500).json({ error: 'Internal Server Error' });
    }
  }
}

module.exports = AuthController;
