/** PM2 config — run from project root: pm2 start ecosystem.config.cjs */
module.exports = {
    apps: [
        {
            name: 'zaha-tryon',
            script: 'dist/index.js',
            node_args: '-r dotenv/config',
            cwd: __dirname,
            instances: 1,
            autorestart: true,
            max_memory_restart: '512M',
            env: {
                NODE_ENV: 'production',
                PORT: 3001,
            },
        },
    ],
};
