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


namespace VRPay\Sdk\Test;

use PHPUnit\Framework\TestCase;
use VRPay\Sdk\ApiClient;
use VRPay\Sdk\Http\HttpClientFactory;
use VRPay\Sdk\Model\AddressCreate;
use VRPay\Sdk\Model\LineItemCreate;
use VRPay\Sdk\Model\LineItemType;
use VRPay\Sdk\Model\TransactionCreate;
use VRPay\Sdk\Service\TransactionPaymentPageService;
use VRPay\Sdk\Service\TransactionService;

/**
 * This class tests the basic functionality of the SDK.
 *
 * @category Class
 * @package  VRPay\Sdk
 * @author   VR pay
 * @license  http://www.apache.org/licenses/LICENSE-2.0 Apache License v2
 */
class TransactionPaymentPageServiceTest extends TestCase
{

    /**
     * @var VRPay\Sdk\ApiClient
     */
    private $apiClient;

    /**
     * @var VRPay\Sdk\Model\TransactionCreate
     */
    private $transactionPayload;

    /**
     * @var int
     */
    private $spaceId = 405;

    /**
     * @var int
     */
    private $userId = 512;

    /**
     * @var string
     */
    private $secret = 'FKrO76r5VwJtBrqZawBspljbBNOxp5veKQQkOnZxucQ=';

    /**
     * Setup before running each test case
     * @return void
     */
    public function setUp() : void
    {
        parent::setUp();

        $this->apiClient = $this->getApiClient();
        $this->transactionPayload = $this->getTransactionPayload();
    }

    /**
     * @return VRPay\Sdk\ApiClient
     */
    private function getApiClient()
    {
        if (is_null($this->apiClient)) {
            $this->apiClient = new ApiClient($this->userId, $this->secret);
            $this->apiClient->setHttpClientType($this->getHttpClient());
        }
        return $this->apiClient;
    }

    /**
     * Get HTTP Client
     *
     * @return mixed
     */
    private function getHttpClient()
    {
        $HttpClientArray = [
            HttpClientFactory::TYPE_CURL,
            HttpClientFactory::TYPE_SOCKET,
        ];
        $httpClientType  = $HttpClientArray[array_rand($HttpClientArray)];
        return $httpClientType;
    }

    /**
     * @return TransactionCreate
     */
    private function getTransactionPayload()
    {
        if (is_null($this->transactionPayload)) {
            // line item
            $lineItem = new LineItemCreate();
            $lineItem->setName('Red T-Shirt');
            $lineItem->setUniqueId('5412');
            $lineItem->setSku('red-t-shirt-123');
            $lineItem->setQuantity(1);
            $lineItem->setAmountIncludingTax(29.95);
            $lineItem->setType(LineItemType::PRODUCT);

            // Customer Billing Address
            $billingAddress = new AddressCreate();
            $billingAddress->setCity('Winterthur');
            $billingAddress->setCountry('CH');
            $billingAddress->setEmailAddress('test@example.com');
            $billingAddress->setFamilyName('Customer');
            $billingAddress->setGivenName('Good');
            $billingAddress->setPostCode('8400');
            $billingAddress->setPostalState('ZH');
            $billingAddress->setOrganizationName('Test GmbH');
            $billingAddress->setPhoneNumber('+41791234567');
            $billingAddress->setSalutation('Ms');

            $this->transactionPayload = new TransactionCreate();
            $this->transactionPayload->setCurrency('CHF');
            $this->transactionPayload->setLineItems([$lineItem]);
            $this->transactionPayload->setAutoConfirmationEnabled(true);
            $this->transactionPayload->setBillingAddress($billingAddress);
            $this->transactionPayload->setShippingAddress($billingAddress);
        }
        return $this->transactionPayload;
    }

    /**
     * Test the cURL HTTP client.
     */
    public function testPaymentPageUrl()
    {
        $transaction    = $this->apiClient->getTransactionService()->create($this->spaceId, $this->getTransactionPayload());
        $paymentPageUrl = $this->apiClient->getTransactionPaymentPageService()->paymentPageUrl($this->spaceId, $transaction->getId());
        $this->assertEquals(0, strpos($paymentPageUrl, 'http'));
    }
}