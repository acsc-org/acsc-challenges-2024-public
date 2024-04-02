// sessionMiddleware.js
exports.checkAuthenticated = (req, res, next) => {
  if (!req.session || !req.session.authenticated) {
    return res.redirect("/login");
  }
  next();
};

exports.check2FARequired = (req, res, next) => {
  const requires2FA = req.session.user && req.session.user.two_factor === 1;
  const is2FAVerified = req.session.verified;

  if (requires2FA && !is2FAVerified) {
    return res.redirect("/2fa");
  }
  next();
};
