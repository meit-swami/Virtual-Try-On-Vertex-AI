/** PM2 config — run from project root: pm2 start ecosystem.config.cjs */
module.exports = {
    apps: [
        {
            name: 'zaha-tryon',
            script: 'dist/index.js',
            node_args: '-r dotenv/config',
            cwd: __dirname,
            exec_mode: 'fork',
            instances: 1,
            autorestart: true,
            max_memory_restart: '512M',
            env: {
                NODE_ENV: 'production',
                PORT: 3001,
                // EC2 often resolves Google hostnames to IPv6 but has no IPv6 route — prefer IPv4
                NODE_OPTIONS: '--dns-result-order=ipv4first',
            },
        },
    ],
};
