import * as JsSIP from 'jssip';

const socket = new JsSIP.WebSocketInterface('ws://ziichat.dev:8080');
const configuration = {
    sockets: [socket],
    uri: 'sip:1000@example.com',
    password: 'password1000'
};

const ua = new JsSIP.UA(configuration);

ua.on('registered', console.log.bind(console));
ua.on('unregistered', console.log.bind(console));
ua.on('registrationFailed', console.error.bind(console));

ua.start();

const eventHandlers = {
    'progress': function (e) {
        console.log('call is in progress');
    },
    'failed': function (e) {
        console.log('call failed with cause: ' + e.data.cause);
    },
    'ended': function (e) {
        console.log('call ended with cause: ' + e.data.cause);
    },
    'confirmed': function (e) {
        console.log('call confirmed');
    }
};

const options = {
    'eventHandlers': eventHandlers,
    'mediaConstraints': {'audio': true, 'video': true}
};

const session = ua.call('sip:bob@ziichat.dev', options);