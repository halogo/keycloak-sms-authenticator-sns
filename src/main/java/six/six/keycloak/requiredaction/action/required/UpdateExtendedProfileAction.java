package six.six.keycloak.requiredaction.action.required;

import org.keycloak.Config;
import org.keycloak.OAuth2Constants;
import org.keycloak.authentication.*;
import org.keycloak.events.Details;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.resources.AttributeFormDataProcessor;
import org.keycloak.services.validation.Validation;
import six.six.keycloak.KeycloakSmsConstants;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.util.List;
import java.util.Objects;

import static six.six.keycloak.authenticator.KeycloakSmsAuthenticatorUtil.isPhoneNumberValid;

public class UpdateExtendedProfileAction implements RequiredActionProvider, RequiredActionFactory, DisplayTypeRequiredActionFactory {
    private static final String USER_ATTRIBUTES_PREFIX = "user.attributes.";
    private static final String FIELD_MOBILE_PREFIX = "mobile_prefix";
    private static final String FIELD_MOBILE_NUMBER = KeycloakSmsConstants.ATTR_MOBILE;
    private static final String FIELD_POSTCODE = USER_ATTRIBUTES_PREFIX + "postcode";
    static final String PROVIDER_ID = "halogo-update-extended-profile";


    @Override
    public void evaluateTriggers(RequiredActionContext context) {
    }

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        Response challenge = context.form()
                .setAttribute("displayMessageImportant", false)
                .createResponse(UserModel.RequiredAction.UPDATE_PROFILE);
        context.challenge(challenge);
    }

    @Override
    public void processAction(RequiredActionContext context) {
        EventBuilder event = context.getEvent();
        event.event(EventType.UPDATE_PROFILE);
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        UserModel user = context.getUser();
        KeycloakSession session = context.getSession();
        RealmModel realm = context.getRealm();

        formData.add("email", user.getEmail());

        List<FormMessage> errors = Validation.validateUpdateProfileForm(realm, formData);

        String mobileNumber = formData.getFirst(FIELD_MOBILE_PREFIX) + formData.getFirst(FIELD_MOBILE_NUMBER);
        if (mobileNumber == null || !(mobileNumber.length() > 0 && isPhoneNumberValid(mobileNumber))) {
            errors.add(new FormMessage(FIELD_MOBILE_NUMBER, six.six.keycloak.requiredaction.action.required.Messages.MOBILE_NUMBER_NO_VALID));
        }

        String postcode = formData.getFirst(FIELD_POSTCODE);
        if (postcode == null || postcode.length() == 0) {
            errors.add(new FormMessage(FIELD_POSTCODE, six.six.keycloak.requiredaction.action.required.Messages.MISSING_POSTCODE));
        }

        if (!errors.isEmpty()) {
            Response challenge = context.form()
                    .setErrors(errors)
                    .setFormData(formData)
                    .createResponse(UserModel.RequiredAction.UPDATE_PROFILE);
            context.challenge(challenge);
            return;
        }

//        if (realm.isEditUsernameAllowed()) {
//            String username = formData.getFirst("username");
//            String oldUsername = user.getUsername();
//
//            boolean usernameChanged = !Objects.equals(oldUsername, username);
//
//            if (usernameChanged) {
//
//                if (session.users().getUserByUsername(username, realm) != null) {
//                    Response challenge = context.form()
//                            .setError(Messages.USERNAME_EXISTS)
//                            .setFormData(formData)
//                            .createResponse(UserModel.RequiredAction.UPDATE_PROFILE);
//                    context.challenge(challenge);
//                    return;
//                }
//
//                user.setUsername(username);
//            }
//
//        }

        user.setFirstName(formData.getFirst("firstName"));
        user.setLastName(formData.getFirst("lastName"));

        String email = formData.getFirst("email");

        String oldEmail = user.getEmail();
        boolean emailChanged = !Objects.equals(oldEmail, email);

        if (emailChanged) {
            if (!realm.isDuplicateEmailsAllowed()) {
                UserModel userByEmail = session.users().getUserByEmail(email, realm);

                // check for duplicated email
                if (userByEmail != null && !userByEmail.getId().equals(user.getId())) {
                    Response challenge = context.form()
                            .setError(Messages.EMAIL_EXISTS)
                            .setFormData(formData)
                            .createResponse(UserModel.RequiredAction.UPDATE_PROFILE);
                    context.challenge(challenge);
                    return;
                }
            }

            user.setEmail(email);
            user.setEmailVerified(false);
        }

        AttributeFormDataProcessor.process(formData, realm, user);

        if (emailChanged) {
            event.clone().event(EventType.UPDATE_EMAIL).detail(Details.PREVIOUS_EMAIL, oldEmail).detail(Details.UPDATED_EMAIL, email).success();
        }
        context.success();
    }


    @Override
    public void close() {

    }

    @Override
    public RequiredActionProvider create(KeycloakSession session) {
        return this;
    }


    @Override
    public RequiredActionProvider createDisplay(KeycloakSession session, String displayType) {
        if (displayType == null) return this;
        if (!OAuth2Constants.DISPLAY_CONSOLE.equalsIgnoreCase(displayType)) return null;
        return UpdateExtendedProfileActionFactory.SINGLETON;
    }


    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public String getDisplayText() {
        return "Update Extended Profile";
    }


    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
