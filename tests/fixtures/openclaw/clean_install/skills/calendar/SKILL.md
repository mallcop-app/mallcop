---
name: calendar
description: Manage calendar events and reminders
version: 2.0.1
author: openclaw-official
tags:
  - calendar
  - productivity
---

# Calendar

Manage your calendar events, create reminders, and schedule meetings.

## Setup

Configure your calendar provider in the skill settings.

## Usage

- "Schedule a meeting tomorrow at 2pm"
- "What do I have on Friday?"
- "Remind me to call Bob in 30 minutes"

## Tools

- `create_event(title, start, end, attendees)`: Create a calendar event
- `list_events(date)`: List events for a given date
- `delete_event(event_id)`: Remove an event

## Permissions

Read/write access to calendar API. No network access beyond configured provider.
