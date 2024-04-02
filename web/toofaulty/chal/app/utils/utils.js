const generateDeviceId = (data) =>
  require("crypto").createHmac("sha1", "2846547907").update(data).digest("hex");

const isTrusted = (user, deviceId) => {
  return user.trusted_device === deviceId;
};

module.exports = {
  generateDeviceId,
  isTrusted,
};
