const jwt = require('jsonwebtoken');

const extractToken = (req) =>
  req.cookies?.accessToken ||
  req.headers.authorization?.split(' ')[1] ||
  req.query?.token;

exports.authenticate = (req, res, next) => {
  try {
    const token = extractToken(req);

    if (!token) {
      return res.status(401).json({ message: 'Unauthorized' });
    }

    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid token' });
  }
};

exports.authorize = (...roles) => (req, res, next) => {
  const currentRole = req.user?.role;
  if (!currentRole || (roles.length && !roles.includes(currentRole))) {
    return res.status(403).json({ message: 'Forbidden' });
  }
  return next();
};
