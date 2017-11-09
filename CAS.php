<?php
/**
 * Copyright 2011-2017 Nick Korbel
 * Copyright 2013-2014 Bart Verheyde
 * Copyright 2013-2014 Bryan Green
 *
 * This file is part of Booked Scheduler.
 *
 * Booked Scheduler is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Booked Scheduler is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Booked Scheduler.  If not, see <http://www.gnu.org/licenses/>.
 */

require_once(ROOT_DIR . 'lib/Application/Authentication/namespace.php');
require_once(ROOT_DIR . 'plugins/Authentication/CAS/namespace.php');

class CAS extends Authentication implements IAuthentication
{
    private $authToDecorate;
    private $registration;

    /**
     * @var CASOptions
     */
    private $options;

    /**
     * @return Registration
     */
    private function GetRegistration()
    {
        if ($this->registration == null) {
            $this->registration = new Registration();
        }

        return $this->registration;
    }

    public function __construct(Authentication $authentication)
    {
        $this->options = new CASOptions();
        $this->setCASSettings();
        $this->authToDecorate = $authentication;
    }

    private function setCASSettings()
    {
        if ($this->options->IsCasDebugOn()) {
            phpCAS::setDebug($this->options->DebugFile());
        }
        phpCAS::client($this->options->CasVersion(), $this->options->HostName(), $this->options->Port(),
            $this->options->ServerUri(), $this->options->ChangeSessionId());
        if ($this->options->CasHandlesLogouts()) {
            phpCAS::handleLogoutRequests(true, $this->options->LogoutServers());
        }

        if ($this->options->HasCertificate()) {
            phpCAS::setCasServerCACert($this->options->Certificate());
        }
        phpCAS::setNoCasServerValidation();
    }

    public function Validate($username, $password)
    {
        try {
            phpCAS::forceAuthentication();

        } catch (Exception $ex) {
            Log::Error('CAS exception: %s', $ex);
            return false;
        }
        return true;
    }

    public function Login($username, $loginContext)
    {
        Log::Debug('Attempting CAS login for username: %s', $username);

        $isAuth = phpCAS::isAuthenticated();
        Log::Debug('CAS is auth ok: %s', $isAuth);
        $username = phpCAS::getUser();
        $this->Synchronize($username);

        return $this->authToDecorate->Login($username, $loginContext);
    }

    public function Logout(UserSession $user)
    {
        Log::Debug('Attempting CAS logout for email: %s', $user->Email);
        $this->authToDecorate->Logout($user);

        if (isset($_SERVER['HTTPS'])) {
            $protocol = ($_SERVER['HTTPS'] && $_SERVER['HTTPS'] != "off") ? "https" : "http";
        } else {
            $protocol = 'http';
        }

        phpCAS::logout(array("url" => $protocol . "://" . dirname($_SERVER['SERVER_NAME'].$_SERVER['REQUEST_URI'])));
    }

    public function AreCredentialsKnown()
    {
        return true;
    }

    public function HandleLoginFailure(IAuthenticationPage $loginPage)
    {
        $this->authToDecorate->HandleLoginFailure($loginPage);
    }

    public function ShowUsernamePrompt()
    {
        return false;
    }

    public function ShowPasswordPrompt()
    {
        return false;
    }

    public function ShowPersistLoginPrompt()
    {
        return false;
    }

    public function ShowForgotPasswordPrompt()
    {
        return false;
    }

    private function Synchronize($username)
    {
        $registration = $this->GetRegistration();

        $casAttributes = phpCAS::getAttributes();

        if ($this->options->IsCasDebugOn()) {
            $this->debugCasAttributes($casAttributes);
        }

        /**
         * sync firstnames
         */
        $firstNamesProperty = $casAttributes[$this->options->MappingFirstname()];
        $firstName = '';

        if (is_array($firstNamesProperty)) {

            foreach ($firstNamesProperty as $singleFirstName) {

                $firstName .= $singleFirstName . ' ';
            }
        } else if (is_string($firstNamesProperty)) {

            $firstName = $firstNamesProperty;
        }
        trim($firstName);

        /**
         * Sync surnames
         */
        $LastNamesProperty = $casAttributes[$this->options->MappingLastname()];
        $lastName = '';

        if (is_array($LastNamesProperty)) {

            foreach ($LastNamesProperty as $singleLastName) {

                $lastName .= $singleLastName . ' ';
            }
        } else if (is_string($LastNamesProperty)) {

            $lastName = $LastNamesProperty;
        }
        trim($lastName);

        /**
         * Sync emails
         */
        $emailProperty = '';
        if (isset($casAttributes['mail'])) $emailProperty = $casAttributes[$this->options->MappingEmail()];

        if (is_array($emailProperty)) {

            $email = $emailProperty[0];
        } else {
            $email = $emailProperty;
        }

        /**
         * Sync Organization
         */
        $organizationProperty = $casAttributes[$this->options->MappingOrganization()];
        $organization = '';

        if (is_array($organizationProperty)) {

            foreach ($organizationProperty as $singleOrganization) {

                $organization .= $singleOrganization . ' ';
            }
        } else if (is_string($organizationProperty)) {

            $organization = $organizationProperty;
        }
        trim($organization);


        $registration->Synchronize(
            new AuthenticatedUser(
                $username, // Username
                $email, // Email
                $firstName, // Firstname
                $lastName, // Lastname
                uniqid(), // Password
                Configuration::Instance()->GetKey(ConfigKeys::LANGUAGE), // Languagecode
                Configuration::Instance()->GetDefaultTimezone(), // Timezone name
                null, // Phone
                $organization, // Organization
                null, // Title
                null // Groups
            ), true
        );
    }

    /**
     * Log CAS-Attributes to apache error log
     *
     * @param array $casAttributes CAS-Attributes for a user
     */
    public function debugCasAttributes($casAttributes)
    {

        /**
         * debug CAS Attributes
         */
        if (is_array($casAttributes)) {

            error_log("CAS-Attributes list:");

            foreach ($casAttributes as $key => $casAttribute) {
                error_log("CAS-Attribute: " . $key . " / " . $casAttribute);

                if (is_array($casAttribute)) {

                    error_log("Sub-Attributes of " . $key);

                    foreach ($casAttribute as $subKey => $casSubAttribute) {

                        error_log("CAS-Sub-Attribute: " . $subKey . " / " . $casSubAttribute);
                    }
                }
            }
        } else {
            error_log("CAS-Attributes is not an array.");
        }
    }
}

?>