# The consent screen and Connected applications

[Back to the README](../README.md)

This page is for everyone who signs in to an application with their Home Assistant account: what you see when an application asks for access, how to choose what it may do, and how to change that or sign it out later.

## Signing in

When an application asks you to sign in with Home Assistant, it sends you to Home Assistant's own login page, the one you know, with two-factor authentication if you use it. If you are already signed in to Home Assistant in that browser, that step is skipped. Then, depending on the application, you see the consent screen, or go straight back to the application.

If the page says "That sign-in request is no longer valid", the sign-in was started more than 10 minutes ago or has already been used. Start again from the application.

## The consent screen

The consent screen asks you to approve or deny the application, in the style of Home Assistant's login page. It names:

- the application, and for one identified by a metadata document, such as Claude, the host that published it, such as `claude.ai`;
- the site you will be sent to;
- what the application will see about you: confirmation of who you are, and, as it asks, your name, your email address and your group memberships.

When the site you will be sent to is on your own computer, as with Claude Code, the screen says so: only approve if you started the sign-in yourself. **Deny** sends the application an `access_denied` error.

The screen is shown for every sign-in through a client an administrator did not register: one identified by a [metadata document](configuration.md#allow-client-metadata-documents), such as Claude, and one that [registered itself](configuration.md#allow-dynamic-client-registration). A client an administrator registered skips it, unless they turned on **Require consent** for it. Clients registered before version 1.6.0 have no consent setting and show the screen until an administrator turns it off; see [Editing a client](clients.md#editing-a-client).

## Choosing what an application may do

An integration that accepts this provider's tokens, such as an MCP server, can describe the access it offers. When an application signs in for such an integration, the consent screen asks what the application may do there:

- It opens on the integration's levels, such as "Look only" or "Control devices", each with one sentence on what it allows. A note appears under the selected level when there is something its name does not say.
- **Choose in detail** shows one setting per area, such as None, Read or Full, with what the current setting means and notes where an area reaches past another. A choice that matches no level is called Custom, with how it differs from the closest level.
- The first time, the integration's default level is selected; after that, your last choice for that application, marked "Your choice last time".
- An area that is unavailable right now, for example because it is turned off in that integration's options, can still be chosen and says why. Settings above what an administrator allows you are locked, with the reason, as is a level that would add nothing you may allow.
- The screen says that what the application can do can be changed, and the application signed out, at any time under [Connected applications](#connected-applications).

Your choice goes into the application's access tokens as scopes, and the integration decides what each scope allows; this provider enforces none of it. A sign-in for such an integration stops on the screen even for a client registered without **Require consent**, since the choice is each person's to make. Your last choice is preselected, so approving is one tap. Sign-ins for anything else work as described above, and an integration that has not described its access gets the plain approve or deny screen.

If the screen says "The access you can allow changed after this page opened", an administrator or the integration changed what you may allow while you were choosing. Check your choice and approve again.

Integration authors: see [Describing a resource to the OIDC Provider](resource-descriptions.md).

## Connected applications

Each person can see the applications signed in with their Home Assistant account on the **Connected applications** page, with when each signed in and was last used, change what each may do, and sign any of them out. Each sign-in is listed on its own, so an application you signed in to twice is listed twice. The page has no entry in the sidebar. You find it:

- at `/oidc_login` on your Home Assistant address, such as `https://your-home-assistant/oidc_login`;
- through the **Connected applications** link in the integration's Configure dialog, under Settings > Devices & services > OIDC Provider > Configure, which only administrators can open;
- by name on the consent screen of an application that signs in for an integration that [describes its access](#choosing-what-an-application-may-do).

For an application that was given a choice of access, the list shows what was chosen: the level's name, or Custom with how it differs from the closest level.

### Signing out

**Sign out** ends that sign-in at once, so the application gets no new access tokens and has to ask you again. An access token it already holds keeps working until it expires, within the hour.

### Changing what an application may do

**Change access**, next to **Sign out**, is there for every application signed in for an integration that [describes its access](#choosing-what-an-application-may-do), also one that signed in before the integration did and has no choice yet. It opens the same choice as the consent screen, the levels and **Choose in detail**, with **Save** and **Cancel** in place of Approve and Deny:

- It opens on what the application has now, named under the heading of **Choose in detail** as the list names it. The option that shows exactly that, a level as the integration holds the levels for you or Custom, is marked "What it has now".
- When you may no longer allow what the application has, for example while the integration holds an area or everything at a lower level, it opens on a choice you may make instead. Above the choice it says so, with the integration's reason, and what saving changes: each area the choice on the screen sets otherwise and what to, or, past three areas, only that saving changes it to that choice. That part follows the choice as you change it. A level is then marked only when it is exactly what the application has and you may not choose it. When part of what the application has is above what you may allow, no option shows it, so none is marked, and **Choose in detail** still names it. Saving changes the access to the choice on the screen; **Cancel** keeps it as it is, as the screen also says above **Save**.
- For an application without a choice yet, nothing is marked. It opens on the access its next refresh would give it. When that refresh would end the sign-in instead, it opens where the consent screen would: on the integration's default level or, when the integration names no access for such sign-ins, on your last choice for that application. A locked default level gives way to the nearest unlocked level below it, or else above it. Saving gives it the access chosen.
- What you may allow, and what is unavailable, are as they are when the page opens, and saving checks the choice with the integration again, as an approval does. When what you may allow changed in between, the choice is shown again with a notice.
- The saved choice replaces the application's access and its scopes, and is your choice for that application at its next sign-in.
- It applies from the application's next token refresh. An access token it already holds keeps its scopes until it expires, within the hour, as after signing it out, and the page says so after saving.

An application that signed in before the integration described its access gets the access the integration names for such sign-ins at its next refresh, without you. [Sign-ins from before an integration described its access](reference.md#sign-ins-from-before-an-integration-described-its-access) has the details.
