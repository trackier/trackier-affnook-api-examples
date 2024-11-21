# Webhook Event Notification System for Group Changes

This project implements a webhook notification system designed to inform clients about changes in groups. Specifically, it sends callbacks for three types of group events:

- **CREATE**: When a new group is created.
- **UPDATE**: When an existing group is updated.
- **DELETE**: When a group is deleted.

Whenever a group event occurs, a callback is sent to the client's configured webhook endpoint with information about the event. The client can then take necessary actions, such as updating their records, synchronizing data, or performing other tasks.

## Why This System Exists

The purpose of this webhook system is to keep clients informed about changes in the group data in real-time. By using this callback system, clients can ensure that they are always up-to-date with the latest group information. This eliminates the need for clients to constantly poll for changes and allows them to react instantly when a group is created, updated, or deleted.

The webhook will send the following details to the client's endpoint:

- **`x-hashed-key`**: A hashed key in headers that generated using the client’s `secret_key` (HMAC SHA-256).
- **`event`**: The type of event (either `CREATE`, `UPDATE`, or `DELETE`).
- **Optionally**, the group data will be sent, including all the client-facing fields.

This ensures that clients have all the necessary information to handle the changes.

## Features

- **Webhook Configuration**: Clients can configure webhook URLs to receive callbacks for group-related events.
- **Event Types**: The system currently supports three event types for groups: `CREATE`, `UPDATE`, and `DELETE`.
- **Secure Hashing**: Every webhook call includes a hashed signature (`hashedVal`) using the client’s `secret_key`, ensuring the authenticity of the event.
- **Optional Group Data**: Clients can receive detailed group data as part of the callback, depending on the event.

## Setup Instructions

### 1. Install Dependencies

Make sure you have **Node.js** and **npm** installed. Then, run the following command to install the required dependencies:

```bash
npm install express crypto cors
node webhook_example.js