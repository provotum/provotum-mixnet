const HtmlWebpackPlugin = require("html-webpack-plugin");
const CopyPlugin = require("copy-webpack-plugin");
const path = require("path");

module.exports = {
  entry: "./src/bootstrap.js",
  output: {
    webassemblyModuleFilename: "[hash].wasm",
    path: path.resolve(__dirname, "dist"),
    filename: "[name].[contenthash].js",
  },
  mode: "development",
  devServer: {
    host: "0.0.0.0",
    port: 8081,
  },
  plugins: [
    new HtmlWebpackPlugin({
      filename: "index.html",
      template: "./src/index.html",
      showErrors: true,
    }),
    new CopyPlugin({
      patterns: [{ from: "./build/styles.css", to: "styles.css" }],
    }),
  ],
  module: {
    rules: [
      {
        test: /\.css$/i,
        use: ["style-loader", "css-loader", "postcss-loader"],
      },
    ],
  },
  experiments: {
    asyncWebAssembly: false,
    topLevelAwait: true,
    syncWebAssembly: true,
  },
  optimization: {
    runtimeChunk: "single",
  },
};
