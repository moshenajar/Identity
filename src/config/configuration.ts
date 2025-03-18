export default() => ({
    port: parseInt(process.env.PORT, 10) || 3001,
    node_env: process.env.NODE_ENV,
    environment_title: process.env.ENVIRONMENT_TITLE,
    database: {
        type: 'postgres',
        host: process.env.DATABASE_HOST || 'localhost',
        port: process.env.DATABASE_PORT || 5432,
        username: process.env.DATABASE_USERNAME,
        password: process.env.DATABASE_PASSWORD,
        name: process.env.DATABASE_NAME,
        ssl: process.env.DATABASE_SSL || false
    }
})