<?php
/**
 * VR pay SDK
 *
 * This library allows to interact with the VR pay payment service.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


namespace VRPay\Sdk\Model;
use \VRPay\Sdk\ObjectSerializer;

/**
 * ClientErrorType model
 *
 * @category    Class
 * @description The type of Client Errors which can be returned by a service.
 * @package     VRPay\Sdk
 * @author      VR pay
 * @license     http://www.apache.org/licenses/LICENSE-2.0 Apache License v2
 */
class ClientErrorType
{
    /**
     * Possible values of this enum
     */
    const END_USER_ERROR = 'END_USER_ERROR';
    const CONFIGURATION_ERROR = 'CONFIGURATION_ERROR';
    const DEVELOPER_ERROR = 'DEVELOPER_ERROR';
    
    /**
     * Gets allowable values of the enum
     * @return string[]
     */
    public static function getAllowableEnumValues()
    {
        return [
            self::END_USER_ERROR,
            self::CONFIGURATION_ERROR,
            self::DEVELOPER_ERROR,
        ];
    }
}


