package com.accolite.pru.health.AuthApp.event.listener;

import com.accolite.pru.health.AuthApp.event.OnUserRegistrationCompleteEvent;
import com.accolite.pru.health.AuthApp.exception.MailSendException;
import com.accolite.pru.health.AuthApp.model.User;
import com.accolite.pru.health.AuthApp.service.MailService;
import com.accolite.pru.health.AuthApp.service.UserService;
import freemarker.template.TemplateException;
import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.stereotype.Component;

import javax.mail.MessagingException;
import java.io.IOException;
import java.util.UUID;

@Component
public class OnUserRegistrationCompleteListener implements ApplicationListener<OnUserRegistrationCompleteEvent> {

	@Autowired
	private UserService userService;

	@Autowired
	private MailService mailService;

	private static final Logger logger = Logger.getLogger(OnUserRegistrationCompleteListener.class);

	/**
	 * As soon as a registration event is complete, invoke the email verification
	 */
	@Override
	public void onApplicationEvent(OnUserRegistrationCompleteEvent onUserRegistrationCompleteEvent) {
		sendEmailVerification(onUserRegistrationCompleteEvent);
	}

	/**
	 * Send email verification to the user and persist the token in the database.
	 */
	private void sendEmailVerification(OnUserRegistrationCompleteEvent event) {
		User user = event.getUser();
		String token = UUID.randomUUID().toString();
		userService.persistEmailVerificationToken(user, token);

		String recipientAddress = user.getEmail();
		String emailConfirmationUrl = event.getRedirectUrl() + token;
		try {
			mailService.sendEmailVerification(emailConfirmationUrl, recipientAddress);
		} catch (IOException | TemplateException | MessagingException e) {
			logger.error(e);
			throw new MailSendException(recipientAddress, "Email Verification");
		}
	}
}
