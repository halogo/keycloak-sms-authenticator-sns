package six.six.keycloak.requiredaction.action.required;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class SMSVerificationRequiredActionFactory implements RequiredActionFactory {
    private static Logger logger = Logger.getLogger(SMSVerificationRequiredActionFactory.class);
    private static final SMSVerificationRequiredAction SINGLETON = new SMSVerificationRequiredAction();

    public RequiredActionProvider create(KeycloakSession session) {
        logger.debug("create called ...");
        return SINGLETON;
    }

    public String getId() {
        logger.debug("getId called ... returning " + SMSVerificationRequiredAction.PROVIDER_ID);
        return SMSVerificationRequiredAction.PROVIDER_ID;
    }

    public String getDisplayText() {
        logger.debug("getDisplayText called ...");
        return "Update Mobile Number";
    }

    public void init(Config.Scope config) {
        logger.debug("init called ...");
        logger.debug(config.get("sms-auth.sms.clientsecret"));
    }

    public void postInit(KeycloakSessionFactory factory) {
        logger.debug("postInit called ...");
    }

    public void close() {
        logger.debug("getId close ...");
    }
}
