// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title CertificateStore
 * @dev Store academic certificates on Ethereum Sepolia Testnet
 */
contract CertificateStore {
    address public admin;

    struct Certificate {    
        string ipfsHash;
        string issuerName;
        address issuerAddress;
        uint256 issuedAt;
        bool exists;
    }

    // Mapping from Certificate ID (e.g., "CERT-1234") to Certificate Struct
    mapping(string => Certificate) public certificates;

    event CertificateIssued(string indexed certificateId, string ipfsHash, address indexed issuer);

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Access Denied: Only Admin can issue certificates");
        _;
    }

    function addCertificate(
        string memory _certificateId, 
        string memory _ipfsHash, 
        string memory _issuerName
    ) public onlyAdmin {
        require(!certificates[_certificateId].exists, "Certificate with this ID already exists");
        
        certificates[_certificateId] = Certificate({
            ipfsHash: _ipfsHash,
            issuerName: _issuerName,
            issuerAddress: msg.sender,
            issuedAt: block.timestamp,
            exists: true
        });

        emit CertificateIssued(_certificateId, _ipfsHash, msg.sender);
    }

    function verifyCertificate(string memory _certificateId) public view returns (
        string memory ipfsHash, 
        string memory issuerName, 
        address issuerAddress, 
        uint256 issuedAt, 
        bool exists
    ) {
        Certificate memory cert = certificates[_certificateId];
        return (cert.ipfsHash, cert.issuerName, cert.issuerAddress, cert.issuedAt, cert.exists);
    }
}
