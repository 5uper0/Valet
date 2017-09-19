//
//  SecureEnclaveValet.swift
//  Valet
//
//  Created by Dan Federman on 9/18/17.
//  Copyright © 2017 Square, Inc.
//
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//

import LocalAuthentication
import Foundation


/// Reads and writes keychain elements that are stored on the Secure Enclave using Accessibility attribute `.whenPasscodeSetThisDeviceOnly`. Accessing these keychain elements will require the user to confirm their presence via Touch ID, Face ID, or passcode entry. If no passcode is set on the device, accessing the keychain via a `SecureEnclaveValet` will fail. Data is removed from the Secure Enclave when the user removes a passcode from the device.
public final class SecureEnclaveValet: NSObject {
    
    // MARK: Flavor
    
    public enum Flavor {
        /// Can read multiple items from the Secure Enclave with only a single user-presence prompt to retrieve multiple items.
        case singlePrompt(SecureEnclaveAccessControl)
        /// Requires a user-presence prompt to retrieve each item in the Secure Enclave.
        case alwaysPrompt(SecureEnclaveAccessControl)
    }
    
    // MARK: Result
    
    public enum Result<Type> {
        /// Data was retrieved from the keychain.
        case success(Type)
        /// User dismissed the user-presence prompt.
        case userCancelled
        /// No data was found for the requested key.
        case itemNotFound
    }
    
    // MARK: Public Class Methods
    
    /// - parameter identifier: A non-empty string that uniquely identifies a SecureEnclaveValet.
    /// - parameter flavor: A description of the SecureEnclaveValet's capabilities.
    /// - returns: A SecureEnclaveValet that reads/writes keychain elements with the desired flavor.
    public class func valet(with identifier: Identifier, of flavor: Flavor) -> SecureEnclaveValet {
        let key = Service.standard(identifier, .secureEnclave(flavor)).description as NSString
        if let existingValet = identifierToValetMap.object(forKey: key) {
            return existingValet
            
        } else {
            let valet = SecureEnclaveValet(identifier: identifier, flavor: flavor)
            identifierToValetMap.setObject(valet, forKey: key)
            return valet
        }
    }
    
    /// - parameter identifier: A non-empty string that must correspond with the value for keychain-access-groups in your Entitlements file.
    /// - parameter flavor: A description of the SecureEnclaveValet's capabilities.
    /// - returns: A SecureEnclaveValet that reads/writes keychain elements that can be shared across applications written by the same development team.
    public class func sharedAccessGroupValet(with identifier: Identifier, of flavor: Flavor) -> SecureEnclaveValet {
        let key = Service.sharedAccessGroup(identifier, .secureEnclave(flavor)).description as NSString
        if let existingValet = identifierToValetMap.object(forKey: key) {
            return existingValet
            
        } else {
            let valet = SecureEnclaveValet(sharedAccess: identifier, flavor: flavor)
            identifierToValetMap.setObject(valet, forKey: key)
            return valet
        }
    }
    
    // MARK: Equatable
    
    /// - returns: `true` if lhs and rhs both read from and write to the same sandbox within the keychain.
    public static func ==(lhs: SecureEnclaveValet, rhs: SecureEnclaveValet) -> Bool {
        return lhs.service == rhs.service
    }
    
    // MARK: Private Class Properties
    
    private static let identifierToValetMap = NSMapTable<NSString, SecureEnclaveValet>.strongToWeakObjects()
    
    // MARK: Initialization
    
    @available(*, deprecated)
    public override init() {
        fatalError("Do not use this initializer")
    }
    
    private init(identifier: Identifier, flavor: Flavor) {
        service = .standard(identifier, .secureEnclave(flavor))
        baseKeychainQuery = service.generateBaseQuery()
        self.flavor = flavor
        self.identifier = identifier
    }
    
    private init(sharedAccess identifier: Identifier, flavor: Flavor) {
        service = .sharedAccessGroup(identifier, .secureEnclave(flavor))
        baseKeychainQuery = service.generateBaseQuery()
        self.flavor = flavor
        self.identifier = identifier
    }
    
    // MARK: Hashable
    
    public override var hashValue: Int {
        return service.description.hashValue
    }
    
    // MARK: Public Properties
    
    public let identifier: Identifier
    public let flavor: Flavor
    
    // MARK: Public Methods
    
    /// - returns: `true` if the keychain is accessible for reading and writing, `false` otherwise.
    /// - note: Determined by writing a value to the keychain and then reading it back out.
    public func canAccessKeychain() -> Bool {
        // To avoid prompting the user for Touch ID or passcode, create a Valet with our identifier and accessibility and ask it if it can access the keychain.
        let noPromptValet: Valet
        switch service {
        case .standard:
            noPromptValet = Valet.valet(with: identifier, of: .vanilla(.whenPasscodeSetThisDeviceOnly))
        case .sharedAccessGroup:
            noPromptValet = Valet.sharedAccessGroupValet(with: identifier, of: .vanilla(.whenPasscodeSetThisDeviceOnly))
        }
        
        return noPromptValet.canAccessKeychain()
    }
    
    /// - parameter object: A Data value to be inserted into the keychain.
    /// - parameter key: A Key that can be used to retrieve the `object` from the keychain.
    /// - returns: `false` if the keychain is not accessible.
    @discardableResult
    public func set(object: Data, for key: Key) -> Bool {
        return execute(in: lock) {
            // Remove the key before trying to set it. This will prevent us from calling SecItemUpdate on an item stored on the Secure Enclave, which would cause iOS to prompt the user for authentication.
            _ = Keychain.removeObject(for: key, options: keychainQuery)
            
            switch Keychain.set(object: object, for: key, options: keychainQuery) {
            case .success:
                return true
                
            case .error:
                return false
            }
        }
    }
    
    /// - parameter key: A Key used to retrieve the desired object from the keychain.
    /// - parameter userPrompt: The prompt displayed to the user in Apple's Face ID, Touch ID, or passcode entry UI.
    /// - returns: The data currently stored in the keychain for the provided key. Returns `nil` if no object exists in the keychain for the specified key, or if the keychain is inaccessible.
    public func object(for key: Key, withPrompt userPrompt: String) -> Result<Data> {
        return execute(in: lock) {
            var secItemQuery = keychainQuery
            if !userPrompt.isEmpty {
                secItemQuery[kSecUseOperationPrompt as String] = userPrompt
            }
            
            switch Keychain.object(for: key, options: secItemQuery) {
            case let .success(data):
                return .success(data)
                
            case let .error(status):
                let userCancelled = (status == errSecUserCanceled || status == errSecAuthFailed)
                if userCancelled {
                    return .userCancelled
                } else {
                    return .itemNotFound
                }
            }
        }
    }
    
    /// - parameter key: The key to look up in the keychain.
    /// - returns: `true` if a value has been set for the given key, `false` otherwise.
    public func containsObject(for key: Key) -> Bool {
        return execute(in: lock) {
            switch Keychain.containsObject(for: key, options: keychainQuery) {
            case .success:
                return true
                
            case let .error(status):
                let keyAlreadyInKeychain = (status == errSecInteractionNotAllowed || status == errSecSuccess)
                return keyAlreadyInKeychain
            }
        }
    }
    
    /// - parameter string: A String value to be inserted into the keychain.
    /// - parameter key: A Key that can be used to retrieve the `string` from the keychain.
    /// @return NO if the keychain is not accessible.
    @discardableResult
    public func set(string: String, for key: Key) -> Bool {
        return execute(in: lock) {
            // Remove the key before trying to set it. This will prevent us from calling SecItemUpdate on an item stored on the Secure Enclave, which would cause iOS to prompt the user for authentication.
            _ = Keychain.removeObject(for: key, options: keychainQuery)
            
            switch Keychain.set(string: string, for: key, options: keychainQuery) {
            case .success:
                return true
                
            case .error:
                return false
            }
        }
    }
    
    /// - parameter key: A Key used to retrieve the desired object from the keychain.
    /// - parameter userPrompt: The prompt displayed to the user in Apple's Face ID, Touch ID, or passcode entry UI.
    /// - returns: The string currently stored in the keychain for the provided key. Returns `nil` if no string exists in the keychain for the specified key, or if the keychain is inaccessible.
    public func string(for key: Key, withPrompt userPrompt: String) -> Result<String> {
        return execute(in: lock) {
            var secItemQuery = keychainQuery
            if !userPrompt.isEmpty {
                secItemQuery[kSecUseOperationPrompt as String] = userPrompt
            }
            
            switch Keychain.string(for: key, options: secItemQuery) {
            case let .success(string):
                return .success(string)
                
            case let .error(status):
                let userCancelled = (status == errSecUserCanceled || status == errSecAuthFailed)
                if userCancelled {
                    return .userCancelled
                } else {
                    return .itemNotFound
                }
            }
        }
    }
    
    /// Require a user to reconfirm their presence on the next query.
    /// - note: This method has no effect on .alwaysPrompt `SecureEnclaveValet`s.
    public func requirePromptOnNextAccess() {
        execute(in: lock) {
            localAuthenticationContext = LAContext()
        }
    }
    
    // TODO: I can do allKeys on .alwaysPrompt. I can't on .singlePrompt
    
    // MARK: Private Properties
    
    private let service: Service
    private let lock = NSLock()
    private let baseKeychainQuery: [String : AnyHashable]
    private var localAuthenticationContext = LAContext()
    
    private var keychainQuery: [String : AnyHashable] {
        switch flavor {
        case .singlePrompt:
            var keychainQuery = baseKeychainQuery
            keychainQuery[kSecUseAuthenticationContext as String] = localAuthenticationContext
            return keychainQuery
            
        case .alwaysPrompt:
            return baseKeychainQuery
        }
    }
}


// Use the `userPrompt` methods to display custom text to the user in Apple's Touch ID, Face ID, and passcode entry UI.
