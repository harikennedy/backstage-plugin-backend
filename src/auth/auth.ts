import { LoggerService, RootConfigService } from "@backstage/backend-plugin-api";
import { HttpError } from "@pagerduty/backstage-plugin-common";

type Auth = {
    authToken: string;
    authTokenExpiryDate: number;
};
type AuthPersistence = {
    [key: string]: Auth;
};
let authPersistence: AuthPersistence = {};
let configService: RootConfigService;
let loggerService: LoggerService;
export function initializeAuth(config: RootConfigService, logger: LoggerService) {
    configService = config;
    loggerService = logger;
}
export async function getAuthToken(annotations?: { [key: string]: string }): Promise<string> {
    const instanceId = annotations?.['pagerduty.com/account'] || 'default';
    const auth = authPersistence[instanceId];
    if (auth &&
        ((auth.authToken.includes('Bearer') && auth.authTokenExpiryDate > Date.now()) ||
        auth.authToken.includes('Token'))) {
        return auth.authToken;
    }
    await loadAuthConfig(instanceId);
    return authPersistence[instanceId].authToken;
}
export async function loadAuthConfig(instanceId: string) {
    try {
        authPersistence[instanceId] = {
            authToken: '',
            authTokenExpiryDate: Date.now()
        };
        const apiKeyPath = instanceId === 'default' ? 'pagerDuty.apiKey' : `pagerDuty.accounts.${instanceId}.apiKey`;
        const oauthPath = instanceId === 'default' ? 'pagerDuty.oauth' : `pagerDuty.accounts.${instanceId}.oauth`;
        if (!configService.getOptionalString(apiKeyPath)) {
            loggerService.warn(`No PagerDuty API token found in config file for instance ${instanceId}. Trying OAuth token instead...`);
            if (!configService.getOptional(oauthPath)) {
                loggerService.error(`No PagerDuty OAuth configuration found in config file for instance ${instanceId}.`);
            } else if (!configService.getOptionalString(`${oauthPath}.clientId`) ||
                       !configService.getOptionalString(`${oauthPath}.clientSecret`) ||
                       !configService.getOptionalString(`${oauthPath}.subDomain`)) {
                loggerService.error(`Missing required PagerDuty OAuth parameters in config file for instance ${instanceId}. 'clientId', 'clientSecret', and 'subDomain' are required. 'region' is optional.`);
            } else {
                authPersistence[instanceId].authToken = await getOAuthToken(
                    configService.getString(`${oauthPath}.clientId`),
                    configService.getString(`${oauthPath}.clientSecret`),
                    configService.getString(`${oauthPath}.subDomain`),
                    configService.getOptionalString(`${oauthPath}.region`) ?? 'us'
                );
                loggerService.info(`PagerDuty OAuth configuration loaded successfully for instance ${instanceId}.`);
            }
        } else {
            authPersistence[instanceId].authToken = `Token token=${configService.getString(apiKeyPath)}`;
            loggerService.info(`PagerDuty API token loaded successfully for instance ${instanceId}.`);
        }
    } catch (error) {
        loggerService.error(`Unable to retrieve valid PagerDuty AUTH configuration from config file for instance ${instanceId}: ${error}`);
    }
}
async function getOAuthToken(clientId: string, clientSecret: string, subDomain: string, region: string): Promise<string> {
    // check if required parameters are provided
    if (!clientId || !clientSecret || !subDomain) {
        throw new Error('Missing required PagerDuty OAuth parameters.');
    }
    // define the scopes required for the OAuth token
    const scopes = `
        abilities.read
        analytics.read
        change_events.read
        escalation_policies.read
        incidents.read
        oncalls.read
        schedules.read
        services.read
        services.write
        standards.read
        teams.read
        users.read
        vendors.read
    `;
    // encode the parameters for the request
    const urlencoded = new URLSearchParams();
    urlencoded.append("grant_type", "client_credentials");
    urlencoded.append("client_id", clientId);
    urlencoded.append("client_secret", clientSecret);
    urlencoded.append("scope", `as_account-${region}.${subDomain} ${scopes}`);
    let response: Response;
    const options: RequestInit = {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: urlencoded,
    };
    const baseUrl = 'https://identity.pagerduty.com/oauth/token';
    try {
        response = await fetch(baseUrl, options);
    } catch (error) {
        throw new Error(`Failed to retrieve oauth token: ${error}`);
    }
    switch (response.status) {
        case 400:
            throw new HttpError("Failed to retrieve valid token. Bad Request - Invalid arguments provided.", 400);
        case 401:
            throw new HttpError("Failed to retrieve valid token. Forbidden - Invalid credentials provided.", 401);
        default: // 200
            break;
    }
    const authResponse = await response.json();
    authPersistence[instanceKey].authTokenExpiryDate = Date.now() + (authResponse.expires_in * 1000);
    return `Bearer ${authResponse.access_token}`;
}