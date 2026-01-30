"""
Base repository interface defining CRUD operations.
"""

from abc import ABC, abstractmethod
from typing import Generic, Optional, TypeVar

from pydantic import BaseModel


T = TypeVar("T", bound=BaseModel)
ID = TypeVar("ID")


class Repository(ABC, Generic[T, ID]):
    """
    Abstract base repository defining standard CRUD operations.
    
    Implementations should handle persistence to specific storage backends
    (file, database, etc.).
    """
    
    @abstractmethod
    async def create(self, entity: T) -> T:
        """
        Create a new entity.
        
        Args:
            entity: The entity to create
            
        Returns:
            The created entity
            
        Raises:
            ValueError: If entity already exists
        """
        pass
    
    @abstractmethod
    async def get(self, id: ID) -> Optional[T]:
        """
        Get an entity by ID.
        
        Args:
            id: The entity identifier
            
        Returns:
            The entity if found, None otherwise
        """
        pass
    
    @abstractmethod
    async def list(
        self,
        skip: int = 0,
        limit: int = 100
    ) -> list[T]:
        """
        List entities with pagination.
        
        Args:
            skip: Number of entities to skip
            limit: Maximum number of entities to return
            
        Returns:
            List of entities
        """
        pass
    
    @abstractmethod
    async def update(self, id: ID, data: dict) -> Optional[T]:
        """
        Update an entity.
        
        Args:
            id: The entity identifier
            data: Dictionary of fields to update
            
        Returns:
            The updated entity if found, None otherwise
        """
        pass
    
    @abstractmethod
    async def delete(self, id: ID) -> bool:
        """
        Delete an entity.
        
        Args:
            id: The entity identifier
            
        Returns:
            True if deleted, False if not found
        """
        pass
    
    @abstractmethod
    async def count(self) -> int:
        """
        Count total entities.
        
        Returns:
            Total number of entities
        """
        pass
    
    @abstractmethod
    async def exists(self, id: ID) -> bool:
        """
        Check if an entity exists.
        
        Args:
            id: The entity identifier
            
        Returns:
            True if exists, False otherwise
        """
        pass
