# Consent screen: choosing what an assistant may do

Mockups for the design in [hass-mcp-server#135](https://github.com/ganhammar/hass-mcp-server/issues/135) and its follow-up on a detailed mode. Nothing here is built. The point is to react to the layout and, as much, to the words.

Open `index.html` in a browser. It shows each page in a phone-sized or wide frame, in light or dark, and lets you switch the situation (first connection, reconnecting, household member with limits). The pages also open on their own; each has a dashed "Mockup" box at the bottom with the same switches and the token scope the choice would produce. Nothing is fetched from the network, so Home Assistant's Roboto font is not loaded and the system font stands in.

| File | What it shows |
|---|---|
| `index.html` | The viewer: page, width, theme and situation switches, the resulting token scope, things to try |
| `consent-simple.html` | The consent screen as it opens: the four levels |
| `consent-detailed.html` | The same prototype opened on "Choose in detail": thirteen areas, each None, Read or Full |
| `connected-applications.html` | `/oidc_login` with what each app was granted and when its access ends |

`consent-simple.html` and `consent-detailed.html` are the same prototype; they differ only in which view they open on, so both directions between the views can be tried from either file.

## How it works

The screen opens on four levels. Below them, "Choose in detail" switches the card to a second view with every area and its setting, and "Back to levels" returns. Both views end with the time limit, the fine print and Approve / Deny, so a person can approve from either.

The levels are presets over the detailed model, so there is one mechanism. The thirteen areas sit in three groups, and each level turns one more group to Full:

| Area | Group | Look only | Control devices | Edit the setup | Administer |
|---|---|---|---|---|---|
| Entities and their states | Devices | Read | Full | Full | Full |
| Calendars | Devices | Read | Full | Full | Full |
| Cameras and images | Devices | Read | Read | Read | Read |
| Automations, scripts and scenes | Setup | Read | Read | Full | Full |
| Dashboards | Setup | Read | Read | Full | Full |
| Helpers | Setup | Read | Read | Full | Full |
| Areas, floors, devices and labels | Setup | Read | Read | Full | Full |
| Templates | Setup | Read | Read | Read | Read |
| KNX | Setup | Read | Read | Full | Full |
| Diagnostics | System | Read | Read | Read | Full |
| Integrations | System | Read | Read | Read | Full |
| Config files | System | Read | Read | Read | Full |
| AppDaemon apps | System | Read | Read | Read | Full |

Cameras and images and Templates have nothing beyond Read, so their rows offer only None and Read.

Picking a level in either view fills the rows. Changing any row so that it matches no level makes the choice "Custom"; changing it back to a level's exact setting makes it that level again. Back in the simple view, a custom choice appears as a fifth option, "Custom", with a summary of how it differs from the closest level, and stays selectable after picking a level so it is not lost by a stray tap.

The token gets the shorthand scope (`mcp:read`, `mcp:control`, `mcp:configure`, `mcp:admin`) when the choice is exactly a level, and one scope per area otherwise (`mcp:<area>:read` or `mcp:<area>:full`, nothing for None). The area names used in the mockup are `entities`, `calendars`, `cameras`, `automations`, `dashboards`, `helpers`, `registries`, `templates`, `knx`, `diagnostics`, `integrations`, `files` and `appdaemon`. The design issue's example, every area Full except Dashboards at Read and no cameras, comes out as twelve area scopes.

## Decisions

**Look only is preselected on a first connection, and the person's last choice for that app on every later one.** The costs are lopsided. A level that is too low costs one tap now, or a message from the assistant later saying it cannot do something. A level that is too high costs nothing visible, which is the problem. The choice sits on the same screen as Approve, so a different level is a tap, not a step. Remembering the last choice (per person and app, marked "Your choice last time") removes the tap for everyone who reconnects, which is most sign-ins after the first.

**The detailed view is a second view in the same card, not an expansion in place.** Expanded under the levels, thirteen rows push Approve about two phone screens down and turn the short path into a long one for everyone who opens it by accident. As its own view it gets a heading, a short explanation and a "Start from a level" picker, and the simple view stays short. It is not a separate page or URL, so nothing is lost on Back and the browser's back button keeps meaning "leave".

**One sentence per level, and one note for the selected level only.** Each description starts with "Also" from the second level on, which says that the levels include each other without a diagram. Anything longer moves to the detailed view. A note appears inside the selected level when there is something its name does not say (reading files for Look only, the reach of actions for Control devices and Edit the setup). Showing it on selection puts it in front of the person at the moment they choose, and keeps the default screen calm.

**Rows describe the current setting, not all three.** Under each control is one sentence saying what that setting gives, which changes as the setting changes. A table of what Read and Full mean for thirteen areas is a wall; one sentence per row says the consequence of what is chosen right now. Screen readers hear each option's sentence while moving through the options, so nothing depends on trying them.

**Honest limits appear where they apply, when they apply, in info style.** They are blue info notes (Home Assistant's `ha-alert` info), not warnings, so the screen stays calm; the page-level orange alert remains the only warning. Each note sits under the row it is about. The two that concern every row, actions and files, sit under Entities and their states and under the System group, which is the last group, right above the time limit and Approve, so everyone scrolls past them before approving. The conditions:

- An area at None shows what still reaches it: for Cameras and images, "Your cameras still show up as entities, and an action can still take a snapshot." Similar notes appear for Calendars, Helpers and Automations, scripts and scenes. Each part appears only when it is true (the entity part only while Entities and their states is above None, the action part only while it is Full).
- Config files or AppDaemon apps at Full, with any other area below Full, shows the files note under the System group. At Read, the note appears only when some other area is at None, since every other area already allows reading.
- Dashboards below Full while Config files is Full says so at the Dashboards row as well, since that is where a person restricting dashboards is looking.
- Entities and their states at Full, with any other area below its maximum, explains that actions reach further.
- Templates at Read while Entities and their states is None explains that templates can still read every state. This one is not in the design issue; it follows from what template rendering can do.

**Unavailable areas stay in the list.** An area whose MCP Server option is off shows its name, a "Not available" pill and the reason, in place. The list keeps the same shape on every install, and the reason tells an administrator where to turn it on.

**Locked options are shown, with the reason, at the option.** A setting above an administrator's ceiling, or turned off in the integration's options, is a visible but disabled segment with a lock icon, and one line under the row says why. A level that would add nothing the person may grant is shown locked with its reason. A level that is only partly above the ceiling stays selectable and is clamped to it; the detailed view shows which rows are held back.

**The time limit defaults to "Until I sign it out".** The main client is a connector that is expected to keep working. Defaulting to an hour would break it silently an hour later. The hint under the control turns the choice into an end time ("Access ends today at 3:42 PM."), and for the default it states the 30-day cap that applies today.

**Connected applications shows the access in the same words as the consent screen.** Each app gets an "Access:" line with the level name, or "Custom" with the same summary, a line saying when access ends (with the chosen limit for time-limited grants, and the 30-day cap otherwise), and a "What it can do" disclosure with the full list. Apps that only sign people in say "Sign-in only" and what they see.

**Home Assistant's own components and tokens, nothing new.** The page, card, alert and buttons follow `oidc-auth-panel.js` and `ha-authorize`. The level options are Home Assistant's `ha-select-box` (bordered option with a radio, label and description, tinted when selected). None / Read / Full and the time limit are `ha-control-select`, the segmented control in Home Assistant's more-info dialogs. Colours, radii, spacing and type sizes are Home Assistant's default theme tokens, light and dark. Two departures, both for legibility: level and area names are 16px medium (the size of a list item headline) instead of the select box's 14px, and the selected segment uses a darker blue in light theme and a lighter one in dark theme (see Accessibility).

## Alternatives considered and rejected

- **Preselecting Control devices.** Fastest for the common case, but it grants actions by default, including the ones the name does not suggest.
- **No preselection, with Approve disabled until a level is picked.** A forced, conscious choice, but a disabled button with no visible reason is a known dead end, and it adds a step to every reconnection.
- **The detailed rows expanding under the levels.** Rejected for length on a phone, as above.
- **A slider or stepper for the four levels.** Compact, but it hides the descriptions, is imprecise on touch, and cannot show a locked level with its reason.
- **On/off per area.** Simpler, but loses the difference between looking and changing, which is the point of the model.
- **A table of all three meanings under every row.** Complete, but long; the one-sentence consequence of the current setting is shorter and more useful.
- **All limits gathered in one box at the bottom.** One place to read, but far from the setting that causes each note.
- **Orange warning style for the limits.** Rejected to keep the screen calm; they are facts about the choice, not alarms.
- **"View" instead of "Read".** "View" reads more naturally for cameras and dashboards, but "Read" matches the scope names and covers files and templates as well.
- **A drop-down for the time limit.** Hides two of three options behind a tap; the segmented control fits on a phone.
- **Listing scopes or tool counts on the screen.** Useful to the developer, meaningless to the person; the mockup shows them only in the dashed mockup box.
- **Grouping unavailable areas at the end.** Shorter list, but the rows would move around between installs, and the reason would be detached from the area.

## Wording

Every string the mockups show, exactly. `{app}` is the client's name from its metadata ("Claude"), `{host}` the host serving its metadata document ("claude.ai"), `{redirect}` the host the person returns to.

### Consent screen, both views

| Where | Text |
|---|---|
| Alert above the card (unchanged) | You're about to give **{app}** from **{host}** access to your Home Assistant instance. |
| Time limit label | Allow access for |
| Time limit options | 1 hour · 1 day · Until I sign it out |
| Hint, 1 hour or 1 day | Access ends today at 3:42 PM. *(or "tomorrow at 2:42 PM.")* |
| Hint, until signed out | Access lasts until you sign {app} out, for 30 days at most. |
| Fine print | When you approve, you go back to **{redirect}**. {app} will also see your name and email address. |
| Buttons (unchanged) | Approve · Deny |
| After approving | **Access approved** / Sending you back to the application. / You can sign {app} out at any time under Connected applications. |
| After denying (unchanged) | **Access denied** / Sending you back to the application. |

The fine print replaces today's "If you continue, you will be sent to … The application will be able to see:" list. The part after "will also see" is built from the requested OpenID scopes, as `SCOPE_DESCRIPTIONS` does today.

### Simple view

| Where | Text |
|---|---|
| Heading (unchanged) | Approve access? |
| Prompt | Choose what {app} can do in Home Assistant. |
| Look only | See devices, history and settings, without changing anything. |
| Control devices | Also turn things on and off, perform actions and manage calendar events. |
| Edit the setup | Also change automations, scripts, scenes, dashboards and helpers, and organize or remove devices and entities. |
| Administer | Also add and remove integrations, change configuration files and AppDaemon apps, and restart Home Assistant. |
| Custom | Like {closest level}, except: *(list of "Area: Setting")*. With more than three differences: Your own choice for each area, closest to {closest level}. |
| Badge | Your choice last time |
| Note, Look only selected, file access on | This includes reading your configuration files and AppDaemon apps. Your secrets.yaml file is never shared. *(Only one of the two is named when only one is on.)* |
| Note, Control devices or Edit the setup selected | Actions reach further than devices. An action can also run a script, turn an automation off or restart Home Assistant. |
| Locked level | Not available for your account. An administrator has limited what you can allow. |
| Link | Choose in detail |

### Detailed view

| Where | Text |
|---|---|
| Back | Back to levels |
| Heading | Choose in detail |
| Intro | For each area, choose None, Read or Full. Read lets {app} look, and Full also lets it make changes. None hides the area's tools, but the things themselves can still show up elsewhere, for example as entities. |
| Picker label | Start from a level |
| Picker options | Look only · Control devices · Edit the setup · Administer · Custom *(shown, not pickable)*; a locked level reads "Administer (not available)" |
| Custom status under the picker | Custom: like {closest level}, except {Area}: {Setting}, {Area}: {Setting}. |
| Group headings | Devices · Setup · System |
| Settings | None · Read · Full |

What each setting says, under the row:

| Area | None | Read | Full |
|---|---|---|---|
| Entities and their states | {app} cannot see states or perform actions. | {app} can see states, history, the logbook and statistics. | {app} can also perform actions and fire events, such as turning lights on and off. |
| Calendars | {app} cannot see or change calendar events. | {app} can see calendar events. | {app} can also add and delete events. |
| Cameras and images | {app} cannot fetch camera images or image files. | {app} can see what your cameras show right now, and saved images such as snapshots. | (none) |
| Automations, scripts and scenes | {app} cannot see or change automations, scripts and scenes. | {app} can see how they are set up and how they last ran. | {app} can also create, change and delete them. |
| Dashboards | {app} cannot see or change dashboards. | {app} can see how your dashboards are set up. | {app} can also create, change and delete dashboards. |
| Helpers | {app} cannot see or change helper settings. | {app} can see your helpers and their settings. | {app} can also create, change and delete helpers. |
| Areas, floors, devices and labels | {app} cannot see or change how your home is organized. | {app} can see your areas, floors, devices and labels. | {app} can also change them, rename entities, and remove entities and devices. |
| Templates | {app} cannot use templates. | {app} can work out values with templates. A template can read any state in your home. | (none) |
| KNX | {app} cannot see KNX telegrams or change KNX entities. | {app} can see recent KNX telegrams and group addresses. | {app} can also create and change KNX entities. |
| Diagnostics | {app} cannot see system health, repairs or logs. | {app} can see system health, repairs, the list of backups and the error log. | {app} can also restart Home Assistant. |
| Integrations | {app} cannot see or manage integrations. | {app} can see which integrations are set up. | {app} can also add, set up, turn off and remove integrations. Removing one also removes its devices. |
| Config files | {app} cannot read or change configuration files. | {app} can read your configuration files, such as configuration.yaml. Never secrets.yaml. | {app} can also change, delete and restore them. A backup is made before every change. |
| AppDaemon apps | {app} cannot read or change AppDaemon apps. | {app} can read the code and settings of your AppDaemon apps. | {app} can also change, delete and restore them. A backup is made before every change. |

Notes, and when they appear:

| Row | Condition | Text |
|---|---|---|
| Entities and their states | Full, and any other area below its maximum | Actions reach further than devices. An action can also run a script, turn an automation off or restart Home Assistant, whatever the other areas say. |
| Calendars | None, Entities above None | Calendars still show up as entities, with their next event. |
| Cameras and images | None, Entities at Read | Your cameras still show up as entities. |
| Cameras and images | None, Entities at Full | Your cameras still show up as entities, and an action can still take a snapshot. |
| Automations, scripts and scenes | None, Entities at Read / Full | They still show up as entities. / They still show up as entities, and an action can still run them or turn them off. |
| Helpers | None, Entities at Read / Full | Helpers still show up as entities. / Helpers still show up as entities, and an action can still change their values. |
| Dashboards | Below Full, Config files at Full | Dashboards kept in YAML files can still be changed through Config files. |
| Dashboards | None, Config files at Read | Dashboards kept in YAML files can still be read through Config files. |
| Templates | Read, Entities at None | Templates can still read the states that Entities and their states hides. |
| Under System | Config files Full, another area below Full | Config files reach past the other areas. {app} can change any YAML file, such as configuration.yaml or a dashboard kept in YAML, whatever the other areas say. |
| Under System | Config files Read, another area at None | Config files reach past the other areas. {app} can read what is written in your YAML files, such as a dashboard kept in YAML, whatever the other areas say. |
| Under System | AppDaemon apps Full, another area below Full | AppDaemon apps are code. A changed app can do anything AppDaemon can do in Home Assistant, whatever the other areas say. |
| Under System | AppDaemon apps Read, another area at None | Reading AppDaemon apps can show passwords and settings for other parts of your home, whatever the other areas say. |

Unavailable and locked:

| Where | Text |
|---|---|
| Unavailable area, pill | Not available |
| Unavailable area, reason | Turned off in the MCP Server integration's options. |
| Locked Full, integration option | Full is turned off in the MCP Server integration's options. |
| Locked Full, ceiling | An administrator has limited this to Read for your account. |

### Connected applications

| Where | Text |
|---|---|
| Heading and intro (unchanged) | Connected applications / These applications can use your Home Assistant account. Signing one out stops it from getting new access; access it already has runs out within the hour. To get access back, it has to ask you again. |
| Name line (unchanged) | **{app}** from {host} |
| Access, level | Access: **Control devices** |
| Access, custom | Access: **Custom** / Like Administer, except: Cameras and images: None, Dashboards: Read *(as a list)* |
| Access, no levels | Access: **Sign-in only.** It sees your name and email address. |
| Ends, time limit | Allowed for 1 day: access ends tomorrow at 9:12 AM. |
| Ends, no time limit | Access lasts until you sign it out, December 3 at the latest. |
| Meta (unchanged words, friendlier dates) | Signed in November 3, last used 2 minutes ago |
| Disclosure | What it can do *(opens the thirteen areas, grouped, each with None, Read or Full)* |
| Button (unchanged) | Sign out |

## Accessibility

- **Native controls.** Levels, None / Read / Full and the time limit are native radio buttons, styled. Arrow keys move within a group and Tab moves between groups, so each area is one tab stop. "Start from a level" is a native select. Nothing needs a custom keyboard handler.
- **Keyboard order.** Simple view: the level group, Choose in detail, the time limit, Approve, Deny. Detailed view: Back to levels, Start from a level, each available area in order (unavailable areas have no stop), the time limit, Approve, Deny. Switching to the detailed view moves focus to Back to levels; going back moves it to the selected level.
- **Names and descriptions.** Each level radio is labelled by the level's name and described by its description, its note and any lock reason (as `ha-select-box` does with `aria-labelledby` and `aria-describedby`). Each area is a `radiogroup` named by the area, and each option is described by what that setting means, so a screen reader announces "Full, radio button, 3 of 3, Claude can also create, change and delete dashboards." A locked option is disabled and also described by its reason. An unavailable area is a group named by the area and described by the reason.
- **Announcements.** The Custom status under the picker and the files note under System are polite live regions, since they change because of something done elsewhere on the page. The notes under a row are not announced; they sit right after the control that changed them and are read next. A note under Dashboards that appears because Config files changed is therefore not announced; if that matters, it can become a live region too.
- **Not colour alone.** A selected level has a filled radio and a border as well as the tint. A selected segment is filled and carries a check mark. A locked segment carries a lock and the reason is written out. An unavailable area says "Not available" with an icon. Every note is a sentence with an icon. The Connected applications list writes None, Read and Full as words.
- **Contrast** (WCAG 2.2, computed from the token values):

  | Pair | Light | Dark |
  |---|---|---|
  | Body text on card | 18.4:1 | 13.0:1 |
  | Secondary text on card | 6.5:1 | 6.1:1 |
  | Description on a selected (tinted) level | 5.2:1 | 4.7:1 |
  | Selected segment label | 6.4:1 | 8.7:1 |
  | Unselected segment label | 16.5:1 | 11.9:1 |
  | Selected segment against its track | 5.7:1 | 9.4:1 |
  | Checked radio against the selected tint | 5.1:1 | 7.8:1 |
  | Deny | 6.5:1 | 5.9:1 |
  | Sign out | 7.0:1 | 5.7:1 |
  | Approve (Home Assistant's default) | 3.3:1 | 3.3:1 |
  | "Choose in detail" (Home Assistant's default) | 3.3:1 | 8.8:1 |

  Home Assistant's selected `ha-control-select` option is white on `#009ac7`, which is 3.3:1, below the 4.5:1 that 14px text needs. The mockups use `#006787` (`--ha-color-primary-30`) with white text in light theme and `#7bd4fb` (`--ha-color-primary-70`) with `#002e3e` text in dark theme. `ha-control-select` hardcodes white for the selected label, so the dark variant needs its own style. The Approve button and the light-theme text button keep Home Assistant's default 3.3:1, since they are `ha-button` as everywhere else in Home Assistant; changing them would be a Home Assistant-wide question.
- **Targets.** Level options are the full card, segments are 32px tall inside a 40px track, buttons are 40px, all above the 24px minimum of WCAG 2.5.8.
- **Text.** Body text is Home Assistant's 14px; level and area names are 16px. Right-to-left names and hosts stay wrapped in `bdi`, as today.
- **Motion.** Only short colour transitions, which Home Assistant already shortens under reduced motion.

## Open questions for you

1. **Which level is preselected?** My answer: Look only on the first connection, the person's last choice for that app afterwards (mocked as "Reconnecting"). Remembering needs a small store per user and client; is that acceptable in the provider, or should the resource server keep it?
2. **Should Control devices carry a visible note that actions are broad?** My answer: yes, shown when the level is selected, as in the mockup. If you build the service filter from the issue's first open question, the note becomes "System actions, such as restarting Home Assistant, need Administer." I would build the filter: without it, a per-user ceiling of Read on Diagnostics does not stop a restart, because an action can still call `homeassistant.restart` while Entities and their states is Full (see 8).
3. **How should the time limit be phrased?** I chose "Allow access for: 1 hour · 1 day · Until I sign it out", defaulting to the last, with the hint showing the exact end time. "Until I sign it out" is not the whole truth while refresh tokens end 30 days after sign-in, so the hint says "for 30 days at most". Alternatives were "No time limit" (untrue) and "Until I revoke it" ("revoke" is jargon). Should a time-limited choice be remembered for the next connection? My answer: no, the time limit should always start at "Until I sign it out".
4. **Second screen or expand in place?** My answer: a second view in the same card, as mocked, for the reasons under Decisions.
5. **How much should the simple view say?** My answer: one sentence per level and one note for the selected level, as mocked. If anything, "Edit the setup" is the longest and could lose "organize or remove devices and entities"; I kept it because removal is the surprising part.
6. **Where does removing devices belong?** Removing entities and devices is in the "Areas, floors, devices and labels" row at Full, so Edit the setup can remove devices, while the issue's level table puts deleting devices under Administer. With three settings per row, the row cannot be split without a fourth setting or a separate area. My answer: accept it and say it in Edit the setup's description, as mocked.
7. **Should Look only read configuration files and AppDaemon apps?** The follow-up defines `mcp:read` as every area at Read, so Look only can read every YAML file (except `secrets.yaml`) and the AppDaemon apps, which often hold passwords written inline. The mockup follows the definition and says so in a note. My answer: leave Config files and AppDaemon apps at None in Look only and Control devices, Read in Edit the setup, Full in Administer.
8. **Actions cut across ceilings, not only rows.** An administrator's ceiling per area is no limit while the person may set Entities and their states to Full: an action can restart Home Assistant, turn automations off, or take a camera snapshot whatever the other rows say. Either the ceiling also covers Entities and their states, or the service filter is required before ceilings ship.
9. **Templates cut across Entities and their states.** A template can read every state, so Templates at Read undoes Entities at None. The mockup says so under Templates. Should the screen go further and lower Templates when Entities is set to None? My answer: no, the note is enough, and coupling rows makes the control harder to predict.
10. **Cameras and images covers two integration options** (camera image access and image file access). When only one is on, Read means only that one. The description would need two more variants ("can see what your cameras show right now" or "can see saved images such as snapshots"). Is that acceptable, or should the row split?
11. **Should KNX be listed when KNX is not set up?** The KNX tools exist on every install and report that KNX is missing. My answer: hide the row when KNX is not set up, but keep showing areas turned off in the MCP Server options, because an administrator can turn those on.
12. **How should a level that is partly over the ceiling look?** The mockup locks a level that adds nothing and offers a partly limited level clamped, silently. My answer: once ceilings exist, add one line to a clamped level, such as "Limited for your account: Diagnostics stays at Read."
13. **How do people find Connected applications?** `/oidc_login` is hidden from the sidebar. The mockup adds "You can sign {app} out at any time under Connected applications" to the approved message, but that message shows only until the redirect. Is a link elsewhere possible, such as the README, the notification after a first sign-in, or a dashboard card?
14. **Changing access without signing out.** Connected applications only signs out. Reducing a grant in place is safe and could come later; widening it should go through the consent screen again. Is that worth an issue?
15. **The selected-segment colours** depart from `ha-control-select` for contrast (see Accessibility). Keep the departure, or stay with Home Assistant's default and accept 3.3:1?
16. **Read-only mode** in the MCP Server options is not mocked. I would lock Control devices, Edit the setup and Administer with "Not available: the MCP Server integration is in read-only mode." and lock every Full segment with the same reason.

## Wording I am least sure of

- "Entities and their states" as an area name. It is accurate for Home Assistant users but carries the most weight (it holds every action) with the least explanation.
- "Actions reach further than devices." It needs to land without alarming anyone; "Actions can do more than control devices." is the plainer fallback.
- "whatever the other areas say", which ends four notes. It is plain, but repeated it may read as a formula.
- "Like Administer, except:" as the summary of a custom choice. Precise, but "Administer" in a summary of a restricted choice may read as more than it is.
- "Until I sign it out" next to a 30-day cap.
