# Documentation for Outlook SMS Addin Backend

## Code Structure

### /config
#### microsoftAuthConfig.js
    This file is used to store the Microsoft Authentication configuration object and stores some constants used throughout the entire codebase, like REDIRECT_URI, POST_LOGOUT_REDIRECT_URI, 
#### Constants:
    REDIRECT_URI: URL where the user is redirected when the user logs in through his Microsoft account.
    GRAPH_ME_ENDPOINT: Microsoft Graph API Endpoint to fetch current user's profile details.
#### database.js
    This contains the code for MySQL database connectivity.

### /controllers
#### MicrosoftOauthController.js
    The controller that handles the requests for the Microsoft OAuth process. It contains the functions bound to specific endpoints to handle the Microsoft sign-in and refreshing access token.
#### Functions:
    handleSignIn(): Handles the sign-in request from the Addin.
    redirectToAuthCodeUrl(): Redirects the user to the Microsoft login page, used by the handleSignIn() function.
    handleRedirect(): Handles the request when the user is redirected back to our backend with an Authorization code by Microsoft. It uses the Authorization code to get the access token. Then the access token is saved into the database.
    handleRefreshTokenRequest(): Handles the request to refresh Access Token. It uses the existing Access Token in the database to verify the user.
    refreshToken(): This is a helper function, used to get the Refresh Token from the Microsoft Auth library instance. Used in handleRedirect(), handleRefreshTokenRequest().
            
### /helpers
#### authenticatedFetch.js
    Contains the helper function to make authenticated requests to Microsoft Graph API.
#### commonHelper.js
    Contains common helper functions used throughout the backend.
#### MicrosoftGraphHelper.js
    Contains helper functions used in making requests to the Graph API.
#### OAuthProxyHelper.js
    This helper file contains the functions to make requests to Auth provider based on the provider of the access token.
            
### /middlewares
#### authMiddleware.js
    Middleware to authenticate the user using the Access Token provided in the Authorization header. It gets the user profile details based on the Auth provider using **OAuthProxyHelper**, to validate the user access token. If the access token is valid then the user is considered valid.
            
### /models
#### accessToken.js
    Contains the functions to create, read, update, and delete the Access Tokens from the database.
#### user.js
Contains the functions to read the users from the database. Currently contains only one function to find a user by email.
            
### /routes
#### authMicrosoft.js
    Registers the routes required for Microsoft OAuth and binds the **MicrosoftOauthController** functions to their specific endpoints.
    /oauth/microsoft/signin - Outlook addin redirects the user to this route. Then the handler redirects the user to the MS login page.
    /oauth/microsoft/redirect - Microsoft redirects the user to this route with an authorization code after authentication.
    /oauth/microsoft/refreshToken - Outlook add-in makes a request to this endpoint to refresh the Access Token when expired.
    /oauth/microsoft/signout - The handler for this route is not currently implemented, but this is used to log the user out and to delete the Access Token from our database, and also from the Microsoft end. So we don't have access to the user's data when the user logs out.

### server.js
    Registers the router middleware **microsoftAuth.js** at "/oauth/microsoft" and contains other code required for the nodejs server.

### .env
    This file contains the variables required for Microsoft OAuth.
    CLOUD_INSTANCE="https://login.microsoftonline.com/" # cloud instance, this will remain the same and will not change
    TENANT_ID="aa87f301-1846-478f-b291-b2699b15b370" # Tenant ID from the APP registered in Microsoft Azure Portal
    CLIENT_ID="ced8c777-cbab-407b-82dc-f1f1cdf570c6" # ID of the APP registered in Microsoft Azure Portal
    CLIENT_SECRET="yA88Q~Yt-w.VoNrNaoHJc8QBrq3OjXj~WsdbKcCf" # Secret for the APP registered in Microsoft Azure Portal
    REDIRECT_URI="https://example.com/oauth/microsoft/redirect" # URL where the user will be redirected after authenticating with Microsoft
    GRAPH_API_ENDPOINT="https://graph.microsoft.com/" # MS Graph API endpoint to fetch the current user's profile
    EXPRESS_SESSION_SECRET="123456789abcdefghijklmnop" # Session secret for the Express APP


## Database Tables

### access_tokens

    Used to store the access tokens generated when user logs in using their Microsoft or Google (currently Microsoft only) Account.

#### Columns

**id**: Identifier for the Access Token.

**access_token**: Actual Access Token String provided by the Authentication provider.

**refresh_token**: Refresh Token String provided by the Authentication provider, used to refresh the Access Token when expired.

**user_id**:ID of the user from the users table, the Access Token is generated for.

**provider**: Authentication provider, Access Token is provided by. (Microsoft / Google / Any other Auth Provider)

**expires_at**: DateTime till the Access Token is valid.

**created_at**: DateTime when Access Token is generated.

**updated_at**: DateTime when Access Token was last updated.