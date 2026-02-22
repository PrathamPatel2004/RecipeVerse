const verifyEmailTemplate = (url, name) => {
  	return `
		<div style="font-family: Arial, sans-serif; max-width: 520px; margin: auto; padding: 20px;">
        	<h2>Hi ${name},</h2>

	        <p>Welcome to <b>Project-Management</b><br/>We’re excited to have you on board.</p>

	        <p>To finish setting up your account, please verify your email address by clicking the button below:</p>

	        <p style="text-align:center; margin: 24px 0;">
      		    <a href="${url}" 
            		 style="background:#4f46e5; color:white; padding:12px 20px; border-radius:6px; text-decoration:none; display:inline-block;">
            		Verify your email
          		</a>
        	</p>

	        <p>This link will expire in <b>15 minutes</b> for security reasons.</p>

    	    <p>If you didn’t create an account with Project-Management, you can safely ignore this email.</p>

	        <p>Need help? Contact us at 
      		    <a href="mailto:patelp149201@gmail.com">patelp149201@gmail.com</a>
        	</p>

	        <p style="margin-top:30px;">Cheers,<br/>— The Project-Management Team</p>
      	</div>
	`;
};

export default verifyEmailTemplate;