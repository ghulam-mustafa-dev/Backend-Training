const nodemailer = require("nodemailer");


const transporter = nodemailer.createTransport({
  service: 'gmail',
  host: process.env.EMAIL_HOST,
  port: Number(process.env.EMAIL_PORT),
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD
  },
});

const sendVerificationEmail = async (email, name, verificationUrl) => {
    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Verify Email',
        html: `
        <body>
            <h3>Email Verification</h3>
            <h4>Hi, ${name}</h4>
            <p>Click the link below to verify your email:</p>
            <a href="${verificationUrl}">${verificationUrl}</a>
        </body>
        `,
    }
    await transporter.sendMail(mailOptions);
}

const sendForgotPasswordEmail = async (email, name, resetPasswordUrl) => {
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'Reset Your Password',
    html: `
    <body>
        <h3>Password Reset</h3>
        <h4>Hi, ${name}</h4>
        <p>Click the link below to reset your password:</p>
        <a href="${resetPasswordUrl}">${resetPasswordUrl}</a>
        <p>This link expires in 15 minutes.</p>
    </body>
    `
  }
  await transporter.sendMail(mailOptions);
}

module.exports = { sendVerificationEmail, sendForgotPasswordEmail };
