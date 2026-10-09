exports.isLoggedIn = (req, res, next) => (req.user ? next() : res.status(401).end());
