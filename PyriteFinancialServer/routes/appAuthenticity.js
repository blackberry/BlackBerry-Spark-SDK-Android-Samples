/*
 * Copyright (c) 2020 BlackBerry Limited. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

var express = require('express');
const fs = require('fs');
const path = require('path');
var router = express.Router();
const storage = require('node-persist');

router.get('/', async(req, res) => {
    let savedAppInstanceIds = await storage.getItem("appInstanceIds")
    let savedAppAuthicityIDs = await storage.getItem("appAuthicityIDs")
    if (savedAppInstanceIds === undefined) {
        savedAppInstanceIds = [];
    }
    if (savedAppAuthicityIDs === undefined) {
        savedAppAuthicityIDs = [];
    }
    res.render('appAuthenticity', { title: 'Pyrite Financial Server', savedAppInstanceIds: savedAppInstanceIds, savedAppAuthicityIDs: savedAppAuthicityIDs});
});

module.exports = router;