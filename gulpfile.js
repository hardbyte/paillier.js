'use strict';

var env = process.env.NODE_ENV || 'development';
var gulp = require('gulp');
var tsc = require('gulp-tsc');
var size = require('gulp-size');
var path = require('path');
var typedoc = require("gulp-typedoc");


gulp.task('tsc', function () {
    return gulp.src(['./src/build.d.ts'])
        .pipe(tsc({
            target: 'es5',
            out: 'index.js',
            outDir: 'dist/',
            emitError: true,
            declaration: true,
            removeComments: env === 'production'
        }))
        .pipe(gulp.dest('dist'))
        .pipe(size({title: 'TypeScript size -> '}));
});

gulp.task("typedoc", function () {
    return gulp
        .src(["src/**/*.ts"])
        .pipe(typedoc({
            module: "commonjs",
            target: "es5",
            out: "docs/",
            name: "paillier.js"
        }))
        ;
});