import fs from "fs";
import crypto from "crypto";

const privateKey = fs.readFileSync("private.pem", "utf8");

function decryptPassword(encrypted) {
  const buffer = Buffer.from(encrypted, "base64");
  const decrypted = crypto.privateDecrypt(
    {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    buffer,
  );
  return decrypted.toString("utf8");
}

// Example: receive encrypted password from client
app.post("/login", (req, res) => {
  const encryptedPwd = req.body.password;
  const password = decryptPassword(encryptedPwd);

  // Now hash + salt password and store/verify
  res.send({ success: true });
});
