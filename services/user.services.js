import { client } from "../index.js";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import { sendEmail } from "../utils/email.js";
import { ObjectId } from "mongodb";

// HASHING THE PASSWORD
const generatePassword = async (password) => {
  const NO_OF_ROUNDS = 10;
  const salt = await bcrypt.genSalt(NO_OF_ROUNDS);
  const hashedPassword = await bcrypt.hash(password, salt);
  return hashedPassword;
};

const dbName = "passwordResetFlow";

// GET ALL USERS
export const getAllUsers = async () => {
  return await client.db(dbName).collection("users").find({}).toArray();
};

// SIGN UP
export const signup = async (req, res, next) => {
  const { name, password, email, company, phone } = req.body;

  const userFromDB = await client
    .db(dbName)
    .collection("users")
    .findOne({ email });

  if (userFromDB) {
    res.status(400).json({
      status: "fail",
      message: "Email already exists",
    });
  } else {
    const hashedPassword = await generatePassword(password);
    const user = await client.db(dbName).collection("users").insertOne({
      name,
      email,
      password: hashedPassword,
      company,
      phone,
      passwordResetToken: "",
      passwordResetExpiresAt: Date,
    });

    res.status(200).json({
      status: "success",
      message: "User signed up successfully",
      data: {
        user,
      },
    });
  }
};

// SIGNUP FINISH
export const signupFinish = async (req, res, next) => {
  let { userId, uniqueString } = req.params;

  const userExists = await client
    .db(dbName)
    .collection("verification")
    .findOne({ userId: ObjectId(userId) });

  if (!userExists) {
    res.status(404).json({
      status: "fail",
      message: "There is no user with this id",
    });
  }

  const expiresAt = userExists.expiresAt;
  const hashString = userExists.uniqueString;

  if (expiresAt < Date.now()) {
    await client
      .db(dbName)
      .collection("verification")
      .deleteOne({ _id: userExists._id });

    await client
      .db(dbName)
      .collection("users")
      .deleteOne({ _id: userExists._id });

    res.status(400).json({
      status: "fail",
      message: "The link has expired, please login again",
    });
  }

  const hashedString = crypto
    .createHash("sha256")
    .update(uniqueString)
    .digest("hex");

  // Finding the user using the hashedString. If user found then the uniqueString matches

  const hashedUser = await client
    .db(dbName)
    .collection("verification")
    .findOne({ uniqueString: hashedString });

  if (!hashedUser) {
    res.status(404).json({
      status: "fail",
      message: "The link is invalid",
    });
  } else {
    await client
      .db(dbName)
      .collection("users")
      .updateOne({ _id: hashedUser.userId }, { $set: { verified: true } });

    res.status(200).json({
      message: "success",
      status: "Signed Up Successfully!",
    });
  }
};

// lOGIN
export const login = async (req, res, next) => {
  const { email, password } = req.body;

  // Check if user exists or not
  const user = await client.db(dbName).collection("users").findOne({ email });

  if (!user) {
    res.status(401).json({
      status: "fail",
      message: "Invalid login credentials!",
    });
  } else {
    if (user.verified === false) {
      return res.status(400).json({
        status: "fail",
        message: "Please verify your email address!",
      });
    }
    const dbPass = user.password;
    const passwordCheck = await bcrypt.compare(password, dbPass);

    if (passwordCheck) {
      const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET_KEY, {
        expiresIn: "90d",
      });

      res.status(200).json({
        status: "success",
        message: "Successful Login",
        token,
        data: user,
      });
    } else {
      res.status(401).json({
        status: "fail",
        message: "Invalid login credentials!",
      });
    }
  }
};

// FORGOT PASSWORD
export const forgotPassword = async (req, res, next) => {
  const user = await client.db(dbName).collection("users").findOne(req.body);

  if (!user) {
    res.status(404).json({
      status: "fail",
      message: "There is no user with this email address",
    });
  }

  // Generate Random token
  const resetToken = crypto.randomBytes(32).toString("hex");

  const passwordResetToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

  // Update Password Reset Token
  const updateUser = await client
    .db(dbName)
    .collection("users")
    .updateOne(
      { _id: user._id },
      {
        $set: {
          passwordResetToken,
          passwordResetExpiresAt: Date.now() + 10 * 60 * 1000,
        },
      }
    );

  // const resetUrl = `${req.protocol}://localhost:3000/resetPassword/${resetToken}`;
  const resetUrl = `https://password-reset-frontend-six.vercel.app/resetPassword/${resetToken}`;

  const message = `Forgot your password? Click on this link to submit a new request to reset your password to: ${resetUrl} .\n This link expires in 10 minutes .\nIf you didn't forget your password, please ignore this email!`;

  try {
    await sendEmail({
      email: user.email,
      subject: "Your password reset token",
      message,
    });

    res.status(200).send({
      status: "success",
      message: "Token sent to email",
    });
  } catch (err) {
    await client
      .db(dbName)
      .collection("users")
      .updateOne(
        { _id: user._id },
        {
          $set: {
            passwordResetToken: "",
          },
        }
      );

    return res.status(500).json({
      status: "fail",
      message: "There was an error sending the email. Please try again later.",
    });
  }
};

// RESET PASSWORD
export const resetPassword = async (req, res, next) => {
  const hashedToken = crypto
    .createHash("sha256")
    .update(req.params.token)
    .digest("hex");

  const user = await client
    .db(dbName)
    .collection("users")
    .findOne({ passwordResetToken: hashedToken });

  if (!user) {
    return res.status(400).json({
      status: "fail",
      message: "Token is invalid or expired",
    });
  }
  if (user.passwordResetExpiresAt < Date.now()) {
    return res.status(404).json({
      status: "fail",
      message:
        "The token has expired, please generate a new password reset link.",
    });
  }

  const hashedPassword = await generatePassword(req.body.password);

  await client
    .db(dbName)
    .collection("users")
    .updateOne(
      { _id: user._id },
      {
        $set: {
          password: hashedPassword,
          passwordResetToken: "",
          passwordResetExpiresAt: "",
        },
      }
    );

  const token = await jwt.sign({ id: user._id }, process.env.JWT_SECRET_KEY, {
    expiresIn: "90d",
  });

  res.status(200).json({
    status: "success",
    token,
    data: user,
  });
};

// CREATE EMAIL LIST
export const emails = async (req, res, next) => {
  const emails = await client
    .db(dbName)
    .collection("email")
    .insertMany(req.body);

  res.status(200).json({
    status: "success",
    data: emails,
  });
};

// AUTH
export const auth = async (req, res, next) => {
  try {
    const token = req.header("token");

    const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);

    const currentUser = await client
      .db(dbName)
      .collection("users")
      .findOne({ _id: ObjectId(decoded.id) });

    if (!currentUser) {
      res.status(401).json({
        status: "fail",
        message: "The user belonging to the token does not exist",
      });
    }

    req.user = currentUser;
    next();
  } catch (err) {
    res.status(401).send({ message: err.message });
  }
};
