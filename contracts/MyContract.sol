// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract CyberInsurance {

    // -------------------------
    // User and Company Structs
    // -------------------------
    struct User {
        address wallet;
        string name;
    }

    struct Policy {
        uint256 riskScore;
        string riskLevel;
    }

    struct Company {
        string name;
        string companyAddress;
        string documentHash; 
    }

    // -------------------------
    // Mappings
    // -------------------------
    mapping(address => User) public users;
    mapping(address => Policy[]) public userPolicies;
    mapping(address => Company[]) public userCompanies;

    // -------------------------
    // User Functions
    // -------------------------
    function registerUser(address _wallet, string memory _name) public {
        users[_wallet] = User(_wallet, _name);
    }

    function getUser(address _wallet) public view returns (string memory) {
        return users[_wallet].name;
    }

    // -------------------------
    // Policy Functions
    // -------------------------
    function storePolicy(uint256 _riskScore, string memory _riskLevel) public {
        userPolicies[msg.sender].push(Policy(_riskScore, _riskLevel));
    }

    function getPolicies(address _user) public view returns (Policy[] memory) {
        return userPolicies[_user];
    }

    // -------------------------
    // Company Functions
    // -------------------------
    function storeCompany(string memory _name, string memory _companyAddress, string memory _documentHash) public {
        userCompanies[msg.sender].push(Company(_name, _companyAddress, _documentHash));
    }

    function getCompanies(address _user) public view returns (Company[] memory) {
        return userCompanies[_user];
    }
}
